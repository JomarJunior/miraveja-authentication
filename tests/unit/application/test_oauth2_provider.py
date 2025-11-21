"""Unit tests for OAuth2Provider."""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import jwt
import pytest

from miraveja_auth.application.configuration import OAuth2Configuration
from miraveja_auth.application.oauth2_provider import OAuth2Provider
from miraveja_auth.domain import (
    AuthenticationException,
    BaseClaims,
    IClaimsParser,
    IOIDCDiscoveryService,
    TokenExpiredException,
    TokenInvalidException,
    User,
)


# Mock Claims implementation for testing
class MockClaims(BaseClaims):
    """Mock Claims for testing."""

    def get_roles(self) -> List[str]:
        return ["user", "admin"]

    def get_client_roles(self, client_id: str) -> List[str]:
        if client_id == "test-client":
            return ["editor"]
        return []

    def get_all_client_roles(self) -> Dict[str, List[str]]:
        return {"test-client": ["editor"]}


class TestOAuth2ProviderInitialization:
    """Test suite for OAuth2Provider initialization."""

    def test_initialization_with_all_parameters(self):
        """Test OAuth2Provider initialization with all parameters."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)

        provider = OAuth2Provider(
            config=config,
            discovery_service=discovery_service,
            claims_parser=claims_parser,
        )

        assert provider._config == config
        assert provider._discovery_service == discovery_service
        assert provider._claims_parser == claims_parser

    def test_initialization_stores_config(self):
        """Test that initialization stores the configuration."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            token_minimum_ttl_seconds=120,
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)

        provider = OAuth2Provider(config, discovery_service, claims_parser)

        assert provider._config.issuer == "https://auth.example.com"
        assert provider._config.client_id == "test-client"
        assert provider._config.token_minimum_ttl_seconds == 120


class TestOAuth2ProviderValidateTokenExpiration:
    """Test suite for token expiration validation."""

    @pytest.mark.asyncio
    async def test_validate_token_with_expired_token(self):
        """Test that expired tokens raise TokenExpiredException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        # Create expired token (exp is in the past)
        current_time = int(datetime.now(timezone.utc).timestamp())
        expired_time = current_time - 3600  # 1 hour ago

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": expired_time,
            "iat": expired_time - 3600,
        }

        # Mock jwt.decode to return expired payload
        with patch("jwt.decode", return_value=payload):
            with pytest.raises(TokenExpiredException) as exc_info:
                await provider.validate_token("fake-token")

            assert exc_info.value.expires_at == expired_time
            assert exc_info.value.ttl == 0

    @pytest.mark.asyncio
    async def test_validate_token_with_insufficient_ttl(self):
        """Test that tokens with insufficient TTL raise TokenExpiredException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            token_minimum_ttl_seconds=120,  # Require at least 2 minutes
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        # Create token with only 30 seconds remaining (less than minimum 120)
        current_time = int(datetime.now(timezone.utc).timestamp())
        expiration = current_time + 30

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": expiration,
            "iat": current_time - 3600,
        }

        with patch("jwt.decode", return_value=payload):
            with pytest.raises(TokenExpiredException) as exc_info:
                await provider.validate_token("fake-token")

            assert exc_info.value.expires_at == expiration
            # TTL should be around 30 seconds (allowing for minor timing differences)
            assert 25 <= exc_info.value.ttl <= 35

    @pytest.mark.asyncio
    async def test_validate_token_with_exact_minimum_ttl(self):
        """Test token with exactly the minimum TTL (should pass with <= check)."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            token_minimum_ttl_seconds=60,
            public_key="test-key",
        )
        discovery_service = AsyncMock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        # Token expires in exactly 60 seconds - with < check this should PASS
        current_time = int(datetime.now(timezone.utc).timestamp())
        expiration = current_time + 60

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": expiration,
            "iat": current_time - 3600,
            "preferred_username": "test_user",
        }

        mock_claims = MockClaims(**payload)
        claims_parser.parse = Mock(return_value=mock_claims)

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            return payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            # Token with TTL == minimum should PASS (check is <, not <=)
            user = await provider.validate_token("fake-token")
            assert user.id == "user-123"


class TestOAuth2ProviderValidateTokenOfflineVerification:
    """Test suite for offline token verification with public key."""

    @pytest.mark.asyncio
    async def test_validate_token_offline_with_valid_token(self):
        """Test successful token validation with offline verification."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...",
            token_verification_algorithm="RS256",
            token_minimum_ttl_seconds=60,
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        # Create valid token payload
        current_time = int(datetime.now(timezone.utc).timestamp())
        expiration = current_time + 3600  # 1 hour from now

        unverified_payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": expiration,
            "iat": current_time,
        }

        verified_payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": expiration,
            "iat": current_time,
            "preferred_username": "john_doe",
            "email": "john@example.com",
        }

        mock_claims = MockClaims(**verified_payload)
        claims_parser.parse = Mock(return_value=mock_claims)

        # Mock jwt.decode to return different values based on verify_signature option
        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return unverified_payload
            return verified_payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            user = await provider.validate_token("fake-token")

            assert isinstance(user, User)
            assert user.id == "user-123"
            assert user.username == "john_doe"
            assert user.email == "john@example.com"
            assert user.realm_roles == ["user", "admin"]
            assert user.client_roles == {"test-client": ["editor"]}

            # Verify discovery service was NOT called (offline verification)
            discovery_service.get_signing_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_token_offline_with_invalid_signature(self):
        """Test that invalid signature raises TokenInvalidException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "exp": current_time + 3600,
        }

        # Mock jwt.decode to raise InvalidTokenError on signature verification
        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            raise jwt.InvalidTokenError("Signature verification failed")

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            with pytest.raises(TokenInvalidException):
                await provider.validate_token("fake-token")


class TestOAuth2ProviderValidateTokenOnlineVerification:
    """Test suite for online token verification with JWKS."""

    @pytest.mark.asyncio
    async def test_validate_token_online_with_valid_token(self):
        """Test successful token validation with online verification."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            # No public_key provided, so should use online verification
        )
        discovery_service = AsyncMock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        expiration = current_time + 3600

        unverified_payload = {
            "iss": "https://auth.example.com",
            "sub": "user-456",
            "aud": "test-client",
            "exp": expiration,
            "iat": current_time,
        }

        verified_payload = {
            **unverified_payload,
            "preferred_username": "jane_doe",
            "email": "jane@example.com",
        }

        mock_claims = MockClaims(**verified_payload)
        claims_parser.parse = Mock(return_value=mock_claims)

        # Mock signing key from discovery service
        mock_signing_key = Mock()
        discovery_service.get_signing_key = AsyncMock(return_value=mock_signing_key)

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return unverified_payload
            return verified_payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            user = await provider.validate_token("fake-token")

            assert isinstance(user, User)
            assert user.id == "user-456"
            assert user.username == "jane_doe"
            assert user.email == "jane@example.com"

            # Verify discovery service WAS called (online verification)
            discovery_service.get_signing_key.assert_called_once_with("fake-token")

    @pytest.mark.asyncio
    async def test_validate_token_online_discovery_service_failure(self):
        """Test that discovery service failure raises AuthenticationException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        discovery_service = AsyncMock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "exp": current_time + 3600,
        }

        # Mock discovery service to raise an exception
        discovery_service.get_signing_key = AsyncMock(side_effect=Exception("JWKS endpoint unavailable"))

        with patch("jwt.decode", return_value=payload) as mock_decode:
            # First call returns unverified payload
            mock_decode.return_value = payload

            with pytest.raises(AuthenticationException) as exc_info:
                await provider.validate_token("fake-token")

            assert "Token validation failed" in str(exc_info.value)


class TestOAuth2ProviderValidateTokenClaimsParser:
    """Test suite for claims parsing."""

    @pytest.mark.asyncio
    async def test_validate_token_calls_claims_parser(self):
        """Test that claims parser is called with verified payload."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="test-key",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        verified_payload = {
            "iss": "https://auth.example.com",
            "sub": "user-789",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        mock_claims = MockClaims(**verified_payload)
        claims_parser.parse = Mock(return_value=mock_claims)

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return verified_payload
            return verified_payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            await provider.validate_token("fake-token")

            # Verify claims parser was called with the verified payload
            claims_parser.parse.assert_called_once_with(verified_payload)

    @pytest.mark.asyncio
    async def test_validate_token_with_minimal_claims(self):
        """Test token validation with minimal claims."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="test-key",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-minimal",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        # Create minimal claims (no optional fields, no roles)
        class MinimalClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        minimal_claims = MinimalClaims(**payload)
        claims_parser.parse = Mock(return_value=minimal_claims)

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            return payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            user = await provider.validate_token("fake-token")

            assert user.id == "user-minimal"
            assert user.username is None
            assert user.email is None
            assert user.realm_roles == []
            assert user.client_roles == {}


class TestOAuth2ProviderValidateTokenExceptions:
    """Test suite for exception handling during token validation."""

    @pytest.mark.asyncio
    async def test_validate_token_jwt_expired_signature_error(self):
        """Test that jwt.ExpiredSignatureError is converted to TokenExpiredException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="test-key",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "exp": current_time + 3600,
        }

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            raise jwt.ExpiredSignatureError("Token has expired")

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            with pytest.raises(TokenExpiredException):
                await provider.validate_token("fake-token")

    @pytest.mark.asyncio
    async def test_validate_token_jwt_invalid_token_error(self):
        """Test that jwt.InvalidTokenError is converted to TokenInvalidException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="test-key",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "exp": current_time + 3600,
        }

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            raise jwt.InvalidTokenError("Invalid token format")

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            with pytest.raises(TokenInvalidException):
                await provider.validate_token("fake-token")

    @pytest.mark.asyncio
    async def test_validate_token_generic_exception(self):
        """Test that generic exceptions are converted to AuthenticationException."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="test-key",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "exp": current_time + 3600,
        }

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            raise ValueError("Unexpected error during token validation")

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            with pytest.raises(AuthenticationException) as exc_info:
                await provider.validate_token("fake-token")

            assert "Token validation failed" in str(exc_info.value)
            assert "Unexpected error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_token_claims_parser_exception(self):
        """Test that claims parser exceptions are handled."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="test-key",
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        # Mock claims parser to raise exception
        claims_parser.parse = Mock(side_effect=ValueError("Invalid payload structure"))

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            return payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            with pytest.raises(AuthenticationException) as exc_info:
                await provider.validate_token("fake-token")

            assert "Token validation failed" in str(exc_info.value)


class TestOAuth2ProviderValidateTokenIntegration:
    """Integration tests for complete token validation flow."""

    @pytest.mark.asyncio
    async def test_complete_validation_flow_offline(self):
        """Test complete validation flow with offline verification."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            public_key="-----BEGIN PUBLIC KEY-----\ntest",
            token_verification_algorithm="RS256",
            token_minimum_ttl_seconds=30,
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "iss": "https://auth.example.com",
            "sub": "integration-user",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
            "preferred_username": "integration_user",
            "email": "integration@example.com",
            "email_verified": True,
        }

        mock_claims = MockClaims(**payload)
        claims_parser.parse = Mock(return_value=mock_claims)

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            return payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            user = await provider.validate_token("integration-token")

            # Verify complete user object
            assert user.id == "integration-user"
            assert user.username == "integration_user"
            assert user.email == "integration@example.com"
            assert user.email_verified is True
            assert "user" in user.realm_roles
            assert "admin" in user.realm_roles
            assert user.client_roles["test-client"] == ["editor"]

            # Verify no online verification was used
            discovery_service.get_signing_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_complete_validation_flow_online(self):
        """Test complete validation flow with online verification."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            # No public_key - triggers online verification
        )
        discovery_service = AsyncMock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        current_time = int(datetime.now(timezone.utc).timestamp())
        payload = {
            "iss": "https://auth.example.com",
            "sub": "online-user",
            "aud": "test-client",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        mock_claims = MockClaims(**payload)
        claims_parser.parse = Mock(return_value=mock_claims)

        mock_signing_key = Mock()
        discovery_service.get_signing_key = AsyncMock(return_value=mock_signing_key)

        def mock_jwt_decode(token, key=None, algorithms=None, **kwargs):
            options = kwargs.get("options", {})
            if options.get("verify_signature") is False:
                return payload
            return payload

        with patch("jwt.decode", side_effect=mock_jwt_decode):
            user = await provider.validate_token("online-token")

            assert user.id == "online-user"

            # Verify online verification was used
            discovery_service.get_signing_key.assert_called_once_with("online-token")

    @pytest.mark.asyncio
    async def test_validation_flow_respects_all_config_options(self):
        """Test that validation respects all configuration options."""
        config = OAuth2Configuration(
            issuer="https://custom-auth.example.com",
            client_id="custom-client",
            public_key="custom-key",
            token_verification_algorithm="HS256",
            token_minimum_ttl_seconds=300,  # 5 minutes
        )
        discovery_service = Mock(spec=IOIDCDiscoveryService)
        claims_parser = Mock(spec=IClaimsParser)
        provider = OAuth2Provider(config, discovery_service, claims_parser)

        # Token with only 4 minutes remaining (less than required 5 minutes)
        current_time = int(datetime.now(timezone.utc).timestamp())
        expiration = current_time + 240  # 4 minutes

        payload = {
            "exp": expiration,
        }

        with patch("jwt.decode", return_value=payload):
            with pytest.raises(TokenExpiredException) as exc_info:
                await provider.validate_token("token-with-low-ttl")

            # Should fail due to insufficient TTL
            assert exc_info.value.ttl < 300
