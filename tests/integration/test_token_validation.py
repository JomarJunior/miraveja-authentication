"""Integration tests for OAuth2Provider + KeycloakClaimsParser token validation."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from miraveja_auth.application.configuration import OAuth2Configuration
from miraveja_auth.application.oauth2_provider import OAuth2Provider
from miraveja_auth.domain.exceptions import (
    AuthenticationException,
    TokenExpiredException,
    TokenInvalidException,
)
from miraveja_auth.infrastructure.providers.keycloak.parser import (
    KeycloakClaimsParser,
)
from miraveja_auth.infrastructure.services.oidc_discovery import OIDCDiscoveryService


class TestOAuth2ProviderKeycloakIntegration:
    """Integration tests for OAuth2Provider with KeycloakClaimsParser."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return OAuth2Configuration(
            issuer="https://keycloak.example.com/realms/test",
            client_id="test-client",
            verify_ssl=True,
            token_minimum_ttl=60,
        )

    @pytest.fixture
    def discovery_service(self, config):
        """Create OIDCDiscoveryService instance."""
        return OIDCDiscoveryService(config)

    @pytest.fixture
    def claims_parser(self):
        """Create KeycloakClaimsParser instance."""
        return KeycloakClaimsParser()

    @pytest.fixture
    def provider(self, config, discovery_service, claims_parser):
        """Create OAuth2Provider instance."""
        return OAuth2Provider(config, discovery_service, claims_parser)

    @pytest.fixture
    def valid_keycloak_payload(self):
        """Create valid Keycloak JWT payload."""
        current_time = int(time.time())
        return {
            "iss": "https://keycloak.example.com/realms/test",
            "sub": "user-123",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
            "jti": "token-id-123",
            "typ": "Bearer",
            "azp": "test-client",
            "preferred_username": "testuser",
            "email": "test@example.com",
            "email_verified": True,
            "realm_access": {"roles": ["user", "admin"]},
            "resource_access": {
                "test-client": {"roles": ["client-admin"]},
                "other-client": {"roles": ["viewer"]},
            },
        }

    @pytest.fixture
    def mock_signing_key(self):
        """Create mock signing key."""
        key = MagicMock()
        key.key = "test-public-key"
        return key

    @pytest.mark.asyncio
    async def test_validate_token_success_with_jwks(self, provider, valid_keycloak_payload, mock_signing_key):
        """Test successful token validation using JWKS."""
        # Create a real JWT token
        token = jwt.encode(valid_keycloak_payload, "test-secret", algorithm="HS256")

        # Mock discovery service to return signing key
        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            # Mock jwt.decode to return our payload
            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = valid_keycloak_payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify user attributes
                assert user.id == "user-123"
                assert user.username == "testuser"
                assert user.email == "test@example.com"
                assert user.email_verified is True
                assert "user" in user.realm_roles
                assert "admin" in user.realm_roles
                assert "client-admin" in user.client_roles.get("test-client", [])
                assert "viewer" in user.client_roles.get("other-client", [])

                # Verify discovery service was called
                mock_get_key.assert_called_once_with(token)

    @pytest.mark.asyncio
    async def test_validate_token_success_with_static_key(
        self, config, discovery_service, claims_parser, valid_keycloak_payload
    ):
        """Test successful token validation using static public key."""
        # Configure with static public key
        config.public_key = "test-static-public-key"
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        token = jwt.encode(valid_keycloak_payload, "test-secret", algorithm="HS256")

        # Mock jwt.decode to return our payload
        with patch("jwt.decode") as mock_decode:
            mock_decode.return_value = valid_keycloak_payload

            # Validate token
            user = await provider.validate_token(token)

            # Verify user was created correctly
            assert user.id == "user-123"
            assert user.username == "testuser"
            assert len(user.realm_roles) == 2
            assert len(user.client_roles) == 2

    @pytest.mark.asyncio
    async def test_validate_token_expired(self, provider, valid_keycloak_payload):
        """Test validation fails for expired token."""
        # Create expired payload
        expired_payload = valid_keycloak_payload.copy()
        expired_payload["exp"] = int(time.time()) - 100

        token = jwt.encode(expired_payload, "test-secret", algorithm="HS256")

        # Validate token - should raise TokenExpiredException
        with pytest.raises(TokenExpiredException) as exc_info:
            await provider.validate_token(token)

        assert "expired" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_validate_token_insufficient_ttl(self, provider, valid_keycloak_payload):
        """Test validation fails when token TTL is below minimum."""
        # Create payload with insufficient TTL (30 seconds, minimum is 60)
        short_ttl_payload = valid_keycloak_payload.copy()
        short_ttl_payload["exp"] = int(time.time()) + 30

        token = jwt.encode(short_ttl_payload, "test-secret", algorithm="HS256")

        # Validate token - should raise TokenExpiredException
        with pytest.raises(TokenExpiredException):
            await provider.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_invalid_signature(self, provider, valid_keycloak_payload, mock_signing_key):
        """Test validation fails for invalid signature."""
        token = jwt.encode(valid_keycloak_payload, "wrong-secret", algorithm="HS256")

        # Mock discovery service
        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            # Mock jwt.decode to raise InvalidTokenError
            with patch("jwt.decode") as mock_decode:
                mock_decode.side_effect = jwt.InvalidTokenError("Invalid signature")

                # Validate token - should raise TokenInvalidException
                with pytest.raises(TokenInvalidException):
                    await provider.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_missing_required_claims(self, provider, mock_signing_key):
        """Test validation fails when required claims are missing."""
        # Create payload missing required BaseClaims fields
        invalid_payload = {
            "sub": "user-123",
            "aud": "test-client",
            # Missing: iss, exp, iat
        }

        token = jwt.encode(invalid_payload, "test-secret", algorithm="HS256")

        # Mock discovery service
        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            # Mock jwt.decode to return invalid payload (but pass expiration check)
            invalid_payload_with_exp: dict = invalid_payload.copy()
            invalid_payload_with_exp["exp"] = int(time.time()) + 3600
            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = invalid_payload_with_exp

                # Validate token - should raise AuthenticationException (wraps TokenInvalidException)
                with pytest.raises(AuthenticationException):
                    await provider.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_jwks_retrieval_failure(self, provider, valid_keycloak_payload):
        """Test validation fails when JWKS retrieval fails."""
        token = jwt.encode(valid_keycloak_payload, "test-secret", algorithm="HS256")

        # Mock discovery service to raise error
        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.side_effect = AuthenticationException("JWKS retrieval failed")

            # Validate token - should raise AuthenticationException
            with pytest.raises(AuthenticationException):
                await provider.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_with_minimal_keycloak_claims(self, provider, mock_signing_key):
        """Test validation with minimal Keycloak claims (no roles)."""
        current_time = int(time.time())
        minimal_payload = {
            "iss": "https://keycloak.example.com/realms/test",
            "sub": "user-456",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "minimaluser",
        }

        token = jwt.encode(minimal_payload, "test-secret", algorithm="HS256")

        # Mock discovery service
        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = minimal_payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify user has no roles
                assert user.id == "user-456"
                assert user.username == "minimaluser"
                assert user.realm_roles == []
                assert user.client_roles == {}

    @pytest.mark.asyncio
    async def test_validate_token_with_complex_role_structure(self, provider, mock_signing_key):
        """Test validation with complex Keycloak role structure."""
        current_time = int(time.time())
        complex_payload = {
            "iss": "https://keycloak.example.com/realms/test",
            "sub": "user-789",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "complexuser",
            "realm_access": {"roles": ["role1", "role2", "role3"]},
            "resource_access": {
                "client1": {"roles": ["admin", "editor"]},
                "client2": {"roles": ["viewer"]},
                "client3": {"roles": ["manager", "analyst", "reporter"]},
            },
        }

        token = jwt.encode(complex_payload, "test-secret", algorithm="HS256")

        # Mock discovery service
        with patch.object(provider._discovery_service, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_signing_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = complex_payload

                # Validate token
                user = await provider.validate_token(token)

                # Verify all roles extracted correctly
                assert len(user.realm_roles) == 3
                assert "role1" in user.realm_roles
                assert "role2" in user.realm_roles
                assert "role3" in user.realm_roles

                assert len(user.client_roles) == 3
                assert len(user.client_roles["client1"]) == 2
                assert len(user.client_roles["client2"]) == 1
                assert len(user.client_roles["client3"]) == 3

                # Verify role checking works
                assert user.has_realm_role("role1")
                assert user.has_client_role("client1", "admin")
                assert user.has_client_role("client3", "reporter")
                assert not user.has_client_role("client1", "nonexistent")


class TestEndToEndTokenValidation:
    """End-to-end integration tests for complete token validation flow."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return OAuth2Configuration(
            issuer="https://keycloak.example.com/realms/production",
            client_id="prod-client",
            verify_ssl=True,
            token_minimum_ttl_seconds=30,
        )

    @pytest.fixture
    def provider_stack(self, config):
        """Create complete provider stack (discovery + parser + provider)."""
        discovery = OIDCDiscoveryService(config)
        parser = KeycloakClaimsParser()
        provider = OAuth2Provider(config, discovery, parser)
        return provider, discovery, parser

    @pytest.mark.asyncio
    async def test_complete_validation_flow(self, provider_stack):
        """Test complete flow from token to authenticated user."""
        provider, discovery, parser = provider_stack

        # Create realistic Keycloak token
        current_time = int(time.time())
        payload = {
            "iss": "https://keycloak.example.com/realms/production",
            "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "aud": "prod-client",
            "exp": current_time + 1800,
            "iat": current_time,
            "jti": "token-uuid-12345",
            "typ": "Bearer",
            "azp": "prod-client",
            "preferred_username": "john.doe",
            "email": "john.doe@company.com",
            "email_verified": True,
            "given_name": "John",
            "family_name": "Doe",
            "realm_access": {"roles": ["user", "developer", "team-lead"]},
            "resource_access": {
                "prod-client": {"roles": ["app-admin", "api-access"]},
                "analytics-service": {"roles": ["data-viewer"]},
            },
            "scope": "openid profile email",
        }

        token = jwt.encode(payload, "secret-key", algorithm="HS256")

        # Mock JWKS key retrieval
        mock_key = MagicMock()
        mock_key.key = "test-key"

        with patch.object(discovery, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Execute validation
                user = await provider.validate_token(token)

                # Verify complete user object
                assert user.id == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                assert user.username == "john.doe"
                assert user.email == "john.doe@company.com"
                assert user.email_verified is True

                # Verify realm roles
                assert len(user.realm_roles) == 3
                assert user.has_realm_role("user")
                assert user.has_realm_role("developer")
                assert user.has_realm_role("team-lead")
                assert not user.has_realm_role("admin")

                # Verify client roles
                assert len(user.client_roles) == 2
                assert user.has_client_role("prod-client", "app-admin")
                assert user.has_client_role("prod-client", "api-access")
                assert user.has_client_role("analytics-service", "data-viewer")
                assert not user.has_client_role("prod-client", "nonexistent")

                # Verify authorization methods work
                user.require_realm_role("user")  # Should not raise
                user.require_client_role("prod-client", "app-admin")  # Should not raise

                from miraveja_auth.domain.exceptions import AuthorizationException

                with pytest.raises(AuthorizationException):
                    user.require_realm_role("admin")

                with pytest.raises(AuthorizationException):
                    user.require_client_role("prod-client", "nonexistent-role")

    @pytest.mark.asyncio
    async def test_validation_flow_with_empty_roles(self, provider_stack):
        """Test validation flow when token has no roles."""
        provider, discovery, _ = provider_stack

        current_time = int(time.time())
        payload = {
            "iss": "https://keycloak.example.com/realms/production",
            "sub": "user-no-roles",
            "aud": "prod-client",
            "exp": current_time + 1800,
            "iat": current_time,
            "preferred_username": "noroles",
            "email": "noroles@company.com",
            # No realm_access or resource_access
        }

        token = jwt.encode(payload, "secret-key", algorithm="HS256")

        mock_key = MagicMock()
        mock_key.key = "test-key"

        with patch.object(discovery, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.return_value = mock_key

            with patch("jwt.decode") as mock_decode:
                mock_decode.return_value = payload

                # Execute validation
                user = await provider.validate_token(token)

                # Verify user has no roles
                assert user.realm_roles == []
                assert user.client_roles == {}
                assert not user.has_realm_role("any-role")
                assert not user.has_client_role("any-client", "any-role")

    @pytest.mark.asyncio
    async def test_validation_flow_error_propagation(self, provider_stack):
        """Test that errors propagate correctly through the stack."""
        provider, discovery, _ = provider_stack

        token = "invalid.jwt.token"

        # Simulate JWKS failure
        with patch.object(discovery, "get_signing_key", new_callable=AsyncMock) as mock_get_key:
            mock_get_key.side_effect = AuthenticationException("OIDC discovery failed: Connection timeout")

            # Should propagate as AuthenticationException
            with pytest.raises(AuthenticationException):
                await provider.validate_token(token)
