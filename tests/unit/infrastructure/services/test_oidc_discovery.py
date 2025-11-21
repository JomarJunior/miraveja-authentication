"""Unit tests for OIDCDiscoveryService."""

from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from jwt import PyJWKClient

from miraveja_auth.application import OAuth2Configuration
from miraveja_auth.domain import AuthenticationException
from miraveja_auth.infrastructure.services import OIDCDiscoveryService


class TestOIDCDiscoveryServiceInitialization:
    """Test OIDCDiscoveryService initialization."""

    def test_init_stores_configuration(self):
        """Test that __init__ stores OAuth2Configuration."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            verify_ssl=True,
        )
        service = OIDCDiscoveryService(config)

        assert service._config is config
        assert service._oidc_config is None
        assert service._jwks_uri is None
        assert service._jwks_client is None
        assert service._cache_expiry == 0.0
        assert service._cache_ttl_seconds == 3600

    def test_init_with_verify_ssl_false(self):
        """Test initialization with SSL verification disabled."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            verify_ssl=False,
        )
        service = OIDCDiscoveryService(config)

        assert service._config.verify_ssl is False


class TestOIDCDiscoveryServiceDiscoverConfiguration:
    """Test discover_configuration method."""

    @pytest.mark.asyncio
    async def test_discover_configuration_success(self):
        """Test successful OIDC configuration discovery."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        expected_config = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/auth",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks",
        }

        mock_response = MagicMock()
        mock_response.json.return_value = expected_config
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = await service.discover_configuration()

            assert result == expected_config
            assert service._oidc_config == expected_config
            mock_client.get.assert_called_once_with("https://auth.example.com/.well-known/openid-configuration")

    @pytest.mark.asyncio
    async def test_discover_configuration_returns_cached(self):
        """Test that cached configuration is returned without HTTP call."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        cached_config = {"issuer": "https://auth.example.com"}
        service._oidc_config = cached_config

        result = await service.discover_configuration()

        assert result is cached_config
        # No HTTP call should be made

    @pytest.mark.asyncio
    async def test_discover_configuration_http_error(self):
        """Test discovery failure due to HTTP error."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock(),
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(AuthenticationException) as exc_info:
                await service.discover_configuration()

            assert "OIDC discovery failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_discover_configuration_invalid_json_format(self):
        """Test discovery failure when response is not a dictionary."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        mock_response = MagicMock()
        mock_response.json.return_value = ["not", "a", "dict"]  # Invalid format
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(AuthenticationException) as exc_info:
                await service.discover_configuration()

            assert "Invalid OIDC discovery document format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_discover_configuration_network_error(self):
        """Test discovery failure due to network error."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = httpx.ConnectError("Connection failed")
            mock_client_class.return_value = mock_client

            with pytest.raises(AuthenticationException) as exc_info:
                await service.discover_configuration()

            assert "OIDC discovery failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_discover_configuration_with_verify_ssl_false(self):
        """Test discovery with SSL verification disabled."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
            verify_ssl=False,
        )
        service = OIDCDiscoveryService(config)

        expected_config = {"issuer": "https://auth.example.com"}

        mock_response = MagicMock()
        mock_response.json.return_value = expected_config
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            await service.discover_configuration()

            mock_client_class.assert_called_once_with(verify=False)


class TestOIDCDiscoveryServiceEnsureJWKSClient:
    """Test _ensure_jwks_client method."""

    @pytest.mark.asyncio
    async def test_ensure_jwks_client_initializes_client(self):
        """Test that _ensure_jwks_client initializes JWKS client."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        oidc_config = {"jwks_uri": "https://auth.example.com/jwks"}
        service._oidc_config = oidc_config

        with patch("miraveja_auth.infrastructure.services.oidc_discovery.PyJWKClient") as mock_jwk_client_class:
            mock_jwk_client = MagicMock(spec=PyJWKClient)
            mock_jwk_client_class.return_value = mock_jwk_client

            await service._ensure_jwks_client()

            assert service._jwks_client is mock_jwk_client
            assert service._jwks_uri == "https://auth.example.com/jwks"
            assert service._cache_expiry > 0
            mock_jwk_client_class.assert_called_once_with("https://auth.example.com/jwks")

    @pytest.mark.asyncio
    async def test_ensure_jwks_client_uses_cache(self):
        """Test that _ensure_jwks_client uses cached client when valid."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        mock_jwk_client = MagicMock(spec=PyJWKClient)
        service._jwks_client = mock_jwk_client
        service._cache_expiry = datetime.now(timezone.utc).timestamp() + 3600  # Valid cache

        with patch("miraveja_auth.infrastructure.services.oidc_discovery.PyJWKClient") as mock_jwk_client_class:
            await service._ensure_jwks_client()

            # Should not create new client
            mock_jwk_client_class.assert_not_called()
            assert service._jwks_client is mock_jwk_client

    @pytest.mark.asyncio
    async def test_ensure_jwks_client_refreshes_expired_cache(self):
        """Test that _ensure_jwks_client refreshes expired cache."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        old_jwk_client = MagicMock(spec=PyJWKClient)
        service._jwks_client = old_jwk_client
        service._cache_expiry = datetime.now(timezone.utc).timestamp() - 1  # Expired cache
        service._oidc_config = {"jwks_uri": "https://auth.example.com/jwks"}
        service._jwks_uri = "https://auth.example.com/jwks"

        with patch("miraveja_auth.infrastructure.services.oidc_discovery.PyJWKClient") as mock_jwk_client_class:
            new_jwk_client = MagicMock(spec=PyJWKClient)
            mock_jwk_client_class.return_value = new_jwk_client

            await service._ensure_jwks_client()

            assert service._jwks_client is new_jwk_client
            assert service._jwks_client is not old_jwk_client

    @pytest.mark.asyncio
    async def test_ensure_jwks_client_discovers_config_when_missing(self):
        """Test that _ensure_jwks_client calls discover_configuration when config is missing."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        oidc_config = {"jwks_uri": "https://auth.example.com/jwks"}

        with patch.object(service, "discover_configuration", new_callable=AsyncMock) as mock_discover:
            mock_discover.return_value = oidc_config

            with patch("miraveja_auth.infrastructure.services.oidc_discovery.PyJWKClient") as mock_jwk_client_class:
                mock_jwk_client = MagicMock(spec=PyJWKClient)
                mock_jwk_client_class.return_value = mock_jwk_client

                await service._ensure_jwks_client()

                mock_discover.assert_called_once()
                assert service._oidc_config == oidc_config

    @pytest.mark.asyncio
    async def test_ensure_jwks_client_raises_when_jwks_uri_missing(self):
        """Test that _ensure_jwks_client raises when JWKS URI is not in config."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        service._oidc_config = {"issuer": "https://auth.example.com"}  # No jwks_uri

        with pytest.raises(AuthenticationException) as exc_info:
            await service._ensure_jwks_client()

        assert "JWKS URI not found" in str(exc_info.value)


class TestOIDCDiscoveryServiceGetSigningKey:
    """Test get_signing_key method."""

    @pytest.mark.asyncio
    async def test_get_signing_key_success(self):
        """Test successful signing key retrieval."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        mock_key = MagicMock()
        mock_jwk_client = MagicMock(spec=PyJWKClient)
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_key

        service._jwks_client = mock_jwk_client
        service._cache_expiry = datetime.now(timezone.utc).timestamp() + 3600

        token = "test.jwt.token"
        result = await service.get_signing_key(token)

        assert result is mock_key
        mock_jwk_client.get_signing_key_from_jwt.assert_called_once_with(token)

    @pytest.mark.asyncio
    async def test_get_signing_key_ensures_client(self):
        """Test that get_signing_key calls _ensure_jwks_client."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        mock_key = MagicMock()
        mock_jwk_client = MagicMock(spec=PyJWKClient)
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_key

        with patch.object(service, "_ensure_jwks_client", new_callable=AsyncMock) as mock_ensure:
            service._jwks_client = mock_jwk_client

            token = "test.jwt.token"
            await service.get_signing_key(token)

            mock_ensure.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_signing_key_raises_when_client_not_initialized(self):
        """Test that get_signing_key raises when JWKS client is not initialized."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="test-client",
        )
        service = OIDCDiscoveryService(config)

        # Mock _ensure_jwks_client to not set the client
        with patch.object(service, "_ensure_jwks_client", new_callable=AsyncMock):
            service._jwks_client = None

            token = "test.jwt.token"
            with pytest.raises(AuthenticationException) as exc_info:
                await service.get_signing_key(token)

            assert "JWKS client is not initialized" in str(exc_info.value)
