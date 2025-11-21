"""Basic usage example."""

import asyncio

from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
)
from miraveja_auth.infrastructure.providers.keycloak import KeycloakClaimsParser


async def main():
    # Configure provider
    config = OAuth2Configuration(
        issuer="https://keycloak.example.com/realms/myrealm",
        client_id="my-client",
    )

    # Create discovery service, claims parser, and provider
    discovery = OIDCDiscoveryService(config)
    parser = KeycloakClaimsParser()
    provider = OAuth2Provider(config, discovery, parser)

    # Validate token
    token = "eyJhbGc..."
    user = await provider.validate_token(token)

    print(f"User: {user.username}")
    print(f"Roles: {user.realm_roles}")

    # Check roles
    if user.has_realm_role("admin"):
        print("User is admin")

    # Require role (raises AuthorizationException if missing)
    user.require_realm_role("user")


if __name__ == "__main__":
    asyncio.run(main())
    asyncio.run(main())
