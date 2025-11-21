from typing import Dict, List, Optional

from pydantic import Field

from miraveja_auth.domain import BaseClaims


class KeycloakClaims(BaseClaims):
    """Keycloak-specific JWT token claims.

    Extends BaseClaims with Keycloak's custom claim structure for roles:
    - realm_access: Contains realm-level roles
    - resource_access: Contains client-specific roles
    """

    realm_access: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description="Keycloak realm access roles",
    )
    resource_access: Optional[Dict[str, Dict[str, List[str]]]] = Field(
        default=None,
        description="Keycloak resource access roles",
    )

    def get_roles(self) -> List[str]:
        """Extract realm roles from Keycloak claims structure.

        Keycloak stores realm roles in: realm_access.roles[]

        Returns:
            List of realm role names.
        """

        if not self.realm_access:
            return []

        return self.realm_access.get("roles", [])

    def get_all_client_roles(self) -> Dict[str, List[str]]:
        """Extract all client-specific roles from Keycloak claims.

        Keycloak stores client roles in: resource_access.<client>.roles[]

        Returns:
            Dictionary mapping client IDs to their respective role lists.
        """
        if not self.resource_access:
            return {}

        result = {}
        for client_id, access in self.resource_access.items():
            roles = access.get("roles", [])
            if roles:
                result[client_id] = roles

        return result

    def get_client_roles(self, client_id: str) -> List[str]:
        """Extract roles for a specific client from Keycloak claims.

        Args:
            client_id: The client ID to extract roles for.

        Returns:
            List of roles for the specified client.
        """
        if not self.resource_access:
            return []

        client_access = self.resource_access.get(client_id, {})
        roles = client_access.get("roles", [])

        return roles
