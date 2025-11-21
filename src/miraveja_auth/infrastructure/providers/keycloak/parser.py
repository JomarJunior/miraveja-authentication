from typing import Any, Dict

from miraveja_auth.domain import BaseClaims, IClaimsParser, TokenInvalidException
from miraveja_auth.infrastructure.providers.keycloak.claims import KeycloakClaims


class KeycloakClaimsParser(IClaimsParser):
    """Parser for Keycloak JWT payloads.

    Converts raw JWT payload dictionaries into KeycloakClaims objects.
    """

    def parse(self, payload: Dict[str, Any]) -> BaseClaims:
        """Parse JWT payload into KeycloakClaims.

        Args:
            payload: Raw JWT token payload (decoded dict).

        Returns:
            KeycloakClaims instance.

        Raises:
            TokenInvalidError: Payload structure is invalid.
        """

        try:
            return KeycloakClaims.model_validate(payload)
        except Exception as e:
            raise TokenInvalidException() from e
