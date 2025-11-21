from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from miraveja_auth.domain.models import BaseClaims, User


class IOAuth2Provider(ABC):
    """Interface for an OAuth2 identity provider.
    This abstract base class defines the standard contract for interacting with
    an OAuth2 identity provider. Implementations of this interface are
    responsible for validating an OAuth2 access token and retrieving user
    information from the provider.
    This abstraction allows the application to support various identity providers
    (e.g., Google, Azure AD, Keycloak) in a pluggable manner. Each concrete
    implementation should handle the specifics of its provider's token
    validation logic, such as fetching public keys, checking issuer claims,
    and mapping provider-specific user data to the application's `User` model.
    """

    @abstractmethod
    async def validate_token(self, token: str) -> User:
        """Validate JWT token and return authenticated user.

        Args:
            token: JWT access token string.

        Returns:
            Authenticated User with roles.

        Raises:
            TokenExpiredError: Token has expired.
            TokenInvalidError: Token is invalid.
            AuthenticationError: Other validation errors.
        """


class IClaimsParser(ABC):
    """Interface for parsing JWT claims into provider-specific Claims objects.
    This abstract base class defines the contract for parsing raw JWT payloads
    into structured Claims objects that are specific to an OAuth2 provider.
    """

    @abstractmethod
    def parse(self, payload: Dict[str, Any]) -> BaseClaims:
        """Parse JWT payload into provider-specific Claims object.

        Args:
            payload: Raw JWT token payload (decoded dict).

        Returns:
            Provider-specific Claims instance (inherits from BaseClaims).

        Raises:
            TokenInvalidError: Payload structure is invalid.
        """


class IOIDCDiscoveryService(ABC):
    """Interface for OIDC Discovery Service.
    This abstract base class defines the contract for discovering OpenID Connect
    configuration from an identity provider's well-known endpoint.
    Implementations of this interface are responsible for fetching and parsing
    the OIDC discovery document, which contains important endpoints and
    configuration details needed for OAuth2 flows.
    """

    @abstractmethod
    async def get_signing_key(self, token: str) -> Any:
        """Get signing key for JWT token validation.

        Args:
            token: JWT token to extract key ID from.

        Returns:
            Signing key for verification.

        Raises:
            AuthenticationError: Key retrieval failed.
        """

    @abstractmethod
    async def discover_configuration(self) -> Dict[str, Any]:
        """Fetch OIDC discovery configuration.

        Returns:
            OIDC configuration dictionary.

        Raises:
            AuthenticationError: Discovery failed.
        """


class IAuthenticator(ABC):
    """Interface for an Authenticator.
    This abstract base class defines the contract for authenticating users
    based on access tokens. Implementations of this interface are responsible
    for validating tokens, retrieving user information, and enforcing
    authentication policies.
    """

    @abstractmethod
    async def get_current_user(self, *args: Any, **kwargs: Any) -> User:
        """Get current authenticated user (required).

        Returns:
            Authenticated User.

        Raises:
            Framework-specific exception if authentication fails.
        """

    @abstractmethod
    async def get_current_user_optional(self, *args: Any, **kwargs: Any) -> Optional[User]:
        """Get current authenticated user (optional).

        Returns:
            Authenticated User or None if not authenticated.
        """

    @abstractmethod
    def require_realm_role(self, role_name: str) -> Any:
        """Dependency to require a realm role for the current user.

        Args:
            role_name: Required realm role name.

        Returns:
            Framework-specific dependency.
        """

    @abstractmethod
    def require_client_role(self, client_id: str, role_name: str) -> Any:
        """Dependency to require a client role for the current user.

        Args:
            client_id: Client ID.
            role_name: Required client role name.

        Returns:
            Framework-specific dependency.
        """
