"""Custom claims parser example for Auth0.

This example shows how to create a custom Claims class and parser
for Auth0 (or any other OAuth2/OIDC provider).
"""

from typing import Any, Dict, List, Optional

from miraveja_auth import (
    BaseClaims,
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    TokenInvalidException,
)
from miraveja_auth.domain.interfaces import IClaimsParser


class Auth0Claims(BaseClaims):
    """Auth0-specific JWT token claims.

    Auth0 stores roles/permissions differently than Keycloak.
    Typically uses custom namespace claims.
    """

    # Auth0-specific fields
    permissions: Optional[List[str]] = None  # Auth0 permissions

    # Custom namespace (configure based on your Auth0 setup)
    # e.g., "https://myapp.com/roles"

    def get_roles(self) -> List[str]:
        """Extract roles from Auth0 claims.

        Auth0 typically uses 'permissions' or custom namespace claims.
        Adjust based on your Auth0 configuration.
        """
        # Option 1: Use permissions as roles
        if self.permissions:
            return self.permissions

        # Option 2: Use custom namespace
        # Pydantic stores extra fields in __pydantic_extra__
        custom_roles = getattr(self, "https://myapp.com/roles", None)
        if custom_roles:
            return custom_roles

        return []

    def get_client_roles(self, client_id: str) -> List[str]:
        """Extract client-specific roles from Auth0 claims.

        Auth0 typically doesn't use client-specific roles.
        Return empty list or implement based on your setup.
        """
        return []

    def get_all_client_roles(self) -> Dict[str, List[str]]:
        """Extract all client roles from Auth0 claims.

        Auth0 typically doesn't use client-specific roles.
        Return empty dict or implement based on your setup.
        """
        return {}


class Auth0ClaimsParser(IClaimsParser):
    """Parser for Auth0 JWT payloads."""

    def parse(self, payload: Dict[str, Any]) -> Auth0Claims:
        """Parse JWT payload into Auth0Claims.

        Args:
            payload: Raw JWT token payload (decoded dict).

        Returns:
            Auth0Claims instance.

        Raises:
            TokenInvalidException: Payload structure is invalid.
        """
        try:
            return Auth0Claims(**payload)
        except Exception as e:
            raise TokenInvalidException() from e


# Usage
async def main():
    config = OAuth2Configuration(
        issuer="https://your-tenant.auth0.com/",
        client_id="your-auth0-client-id",
    )

    discovery = OIDCDiscoveryService(config)
    parser = Auth0ClaimsParser()  # Use Auth0 parser
    provider = OAuth2Provider(config, discovery, parser)

    # Validate token
    token = "eyJhbGc..."
    user = await provider.validate_token(token)

    print(f"User: {user.username}")
    print(f"Permissions: {user.realm_roles}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
    asyncio.run(main())
