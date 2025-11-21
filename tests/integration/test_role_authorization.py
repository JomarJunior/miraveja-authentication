"""Integration tests for role-based authorization.

These tests verify the complete flow from JWT token validation through
claims parsing, role extraction, and role-based authorization checks.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from miraveja_auth.application.configuration import OAuth2Configuration
from miraveja_auth.application.oauth2_provider import OAuth2Provider
from miraveja_auth.domain.exceptions import AuthorizationException
from miraveja_auth.infrastructure.providers.keycloak.parser import (
    KeycloakClaimsParser,
)
from miraveja_auth.infrastructure.services.oidc_discovery import OIDCDiscoveryService


class TestRoleExtractionIntegration:
    """Integration tests for role extraction from Keycloak tokens."""

    @pytest.fixture
    def provider_stack(self):
        """Create complete provider stack."""
        config = OAuth2Configuration(
            issuer="https://keycloak.example.com/realms/test",
            client_id="test-client",
            token_minimum_ttl_seconds=60,
        )
        discovery = OIDCDiscoveryService(config)
        parser = KeycloakClaimsParser()
        provider = OAuth2Provider(config, discovery, parser)
        return provider, config

    @pytest.fixture
    def mock_signing_key(self):
        """Create mock signing key."""
        key = MagicMock()
        key.key = "test-key"
        return key

    @pytest.mark.asyncio
    async def test_realm_roles_extraction_and_validation(self, provider_stack, mock_signing_key):
        """Test complete flow: token → claims → roles → validation."""
        provider, config = provider_stack

        current_time = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "user-123",
            "aud": config.client_id,
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "testuser",
            "realm_access": {"roles": ["user", "developer", "team-lead"]},
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify all realm roles extracted
                assert len(user.realm_roles) == 3
                assert "user" in user.realm_roles
                assert "developer" in user.realm_roles
                assert "team-lead" in user.realm_roles

                # Test role checking methods
                assert user.has_realm_role("user")
                assert user.has_realm_role("developer")
                assert user.has_realm_role("team-lead")
                assert not user.has_realm_role("admin")

                # Test require methods
                user.require_realm_role("user")  # Should not raise
                user.require_realm_role("developer")  # Should not raise

                with pytest.raises(AuthorizationException):
                    user.require_realm_role("admin")

    @pytest.mark.asyncio
    async def test_client_roles_extraction_and_validation(self, provider_stack, mock_signing_key):
        """Test client-specific role extraction and validation."""
        provider, config = provider_stack

        current_time = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "user-456",
            "aud": config.client_id,
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "clientuser",
            "resource_access": {
                "frontend-app": {"roles": ["ui-admin", "editor"]},
                "backend-api": {"roles": ["api-consumer"]},
                "analytics-service": {"roles": ["data-viewer", "report-generator"]},
            },
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify all client roles extracted
                assert len(user.client_roles) == 3
                assert "ui-admin" in user.client_roles["frontend-app"]
                assert "editor" in user.client_roles["frontend-app"]
                assert "api-consumer" in user.client_roles["backend-api"]
                assert "data-viewer" in user.client_roles["analytics-service"]
                assert "report-generator" in user.client_roles["analytics-service"]

                # Test client role checking
                assert user.has_client_role("frontend-app", "ui-admin")
                assert user.has_client_role("frontend-app", "editor")
                assert user.has_client_role("backend-api", "api-consumer")
                assert user.has_client_role("analytics-service", "data-viewer")
                assert not user.has_client_role("frontend-app", "nonexistent")
                assert not user.has_client_role("nonexistent-client", "role")

                # Test require methods
                user.require_client_role("frontend-app", "ui-admin")  # Should not raise
                user.require_client_role("backend-api", "api-consumer")  # Should not raise

                with pytest.raises(AuthorizationException):
                    user.require_client_role("frontend-app", "super-admin")

                with pytest.raises(AuthorizationException):
                    user.require_client_role("nonexistent-client", "role")

    @pytest.mark.asyncio
    async def test_mixed_realm_and_client_roles(self, provider_stack, mock_signing_key):
        """Test extraction and validation of both realm and client roles."""
        provider, config = provider_stack

        current_time = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "user-789",
            "aud": config.client_id,
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "fulluser",
            "realm_access": {"roles": ["user", "admin"]},
            "resource_access": {
                "test-client": {"roles": ["app-admin", "app-user"]},
            },
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify both realm and client roles
                assert len(user.realm_roles) == 2
                assert len(user.client_roles) == 1

                # Test realm roles
                assert user.has_realm_role("user")
                assert user.has_realm_role("admin")

                # Test client roles
                assert user.has_client_role("test-client", "app-admin")
                assert user.has_client_role("test-client", "app-user")

                # Test combined authorization scenarios
                user.require_realm_role("admin")  # Should not raise
                user.require_client_role("test-client", "app-admin")  # Should not raise

    @pytest.mark.asyncio
    async def test_user_with_no_roles(self, provider_stack, mock_signing_key):
        """Test user with no realm or client roles."""
        provider, config = provider_stack

        current_time = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "user-nouser",
            "aud": config.client_id,
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "noroleuser",
            # No realm_access or resource_access
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify no roles
                assert user.realm_roles == []
                assert user.client_roles == {}

                # All role checks should fail
                assert not user.has_realm_role("any-role")
                assert not user.has_client_role("any-client", "any-role")

                # All require calls should raise
                with pytest.raises(AuthorizationException):
                    user.require_realm_role("user")

                with pytest.raises(AuthorizationException):
                    user.require_client_role("any-client", "any-role")

    @pytest.mark.asyncio
    async def test_empty_role_arrays(self, provider_stack, mock_signing_key):
        """Test handling of empty role arrays."""
        provider, config = provider_stack

        current_time = int(time.time())
        payload = {
            "iss": config.issuer,
            "sub": "user-empty",
            "aud": config.client_id,
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "emptyuser",
            "realm_access": {"roles": []},  # Empty array
            "resource_access": {"test-client": {"roles": []}},  # Empty array
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify empty roles
                assert user.realm_roles == []
                assert user.client_roles == {}  # Empty arrays filtered out

                # All checks should fail
                assert not user.has_realm_role("user")
                assert not user.has_client_role("test-client", "role")


class TestAuthorizationExceptionDetails:
    """Test that authorization exceptions contain proper context."""

    def test_realm_role_exception_contains_details(self):
        """Test that realm role authorization exception has proper details."""
        user = User(
            id="user-123",
            username="testuser",
            realm_roles=["user"],
            client_roles={},
        )

        try:
            user.require_realm_role("admin")
            pytest.fail("Should have raised AuthorizationException")
        except AuthorizationException as e:
            # Exception message should contain information about the missing role
            assert "admin" in str(e).lower() or "realm" in str(e).lower()

    def test_client_role_exception_contains_details(self):
        """Test that client role authorization exception has proper details."""
        user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={"test-client": ["viewer"]},
        )

        try:
            user.require_client_role("test-client", "admin")
            pytest.fail("Should have raised AuthorizationException")
        except AuthorizationException as e:
            # Exception message should contain information about the missing role/client
            assert "admin" in str(e).lower() or "client" in str(e).lower()


# Import User at the end to avoid circular import issues
from miraveja_auth.domain.models import User
