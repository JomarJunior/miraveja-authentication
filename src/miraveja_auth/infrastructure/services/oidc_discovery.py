from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from jwt import PyJWKClient

from miraveja_auth.application import OAuth2Configuration
from miraveja_auth.domain import AuthenticationException, IOIDCDiscoveryService


class OIDCDiscoveryService(IOIDCDiscoveryService):
    """OIDC discovery and JWKS service using HTTP.

    Handles external communication with OIDC provider:
    - Fetches .well-known/openid-configuration
    - Retrieves and caches JWKS (JSON Web Key Set)
    - Provides signing keys for JWT validation
    """

    def __init__(self, config: OAuth2Configuration):
        """Initialize discovery service.

        Args:
            config: OAuth2 configuration with issuer URL.
        """

        self._config = config
        self._oidc_config: Optional[Dict[str, Any]] = None
        self._jwks_uri: Optional[str] = None
        self._jwks_client: Optional[PyJWKClient] = None
        self._cache_expiry: float = 0.0
        self._cache_ttl_seconds: int = 3600  # 1 hour cache TTL

    async def discover_configuration(self) -> Dict[str, Any]:
        """Fetch OIDC discovery configuration.

        Returns:
            OIDC configuration dictionary.

        Raises:
            AuthenticationException: Discovery failed.
        """
        if self._oidc_config:
            return self._oidc_config  # Return cached config

        discovery_url = f"{self._config.issuer}/.well-known/openid-configuration"

        async with httpx.AsyncClient(verify=self._config.verify_ssl) as client:
            try:
                response = await client.get(discovery_url)
                response.raise_for_status()
                self._oidc_config = response.json()
                if not isinstance(self._oidc_config, dict):
                    raise AuthenticationException("Invalid OIDC discovery document format")

                return self._oidc_config
            except Exception as e:
                raise AuthenticationException(f"OIDC discovery failed: {str(e)}") from e

    async def _ensure_jwks_client(self) -> None:
        """Ensure JWKS client is initialized and cache is valid."""
        now_epoch: float = datetime.now(timezone.utc).timestamp()
        if self._jwks_client and now_epoch < self._cache_expiry:
            return  # Cache is valid

        if not self._oidc_config:
            self._oidc_config = await self.discover_configuration()

        if not self._jwks_uri:
            self._jwks_uri = self._oidc_config.get("jwks_uri")
            if not self._jwks_uri:
                raise AuthenticationException("JWKS URI not found in OIDC configuration.")

        self._jwks_client = PyJWKClient(self._jwks_uri)
        self._cache_expiry = now_epoch + self._cache_ttl_seconds

    async def get_signing_key(self, token: str) -> Any:
        """Get signing key for JWT token validation.

        Args:
            token: JWT token to extract key ID from.

        Returns:
            Signing key for verification.

        Raises:
            AuthenticationException: Key retrieval failed.
        """
        await self._ensure_jwks_client()
        if not self._jwks_client:
            raise AuthenticationException("JWKS client is not initialized.")

        return self._jwks_client.get_signing_key_from_jwt(token)
