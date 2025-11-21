from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from miraveja_auth.domain.exceptions import AuthorizationException


class Role(BaseModel):
    """Value object representing a role.

    A role represents a permission or access level within the authentication system.
    Roles can be either realm-level (global) or client-specific.

    Attributes:
        id: Unique identifier for the role.
        name: Human-readable role name (e.g., "admin", "editor").
        description: Optional description of the role's purpose.
        composite: Whether this role is composed of other roles.
        client_role: Whether this is a client-specific role.
        container_id: ID of the container (realm or client) that owns this role.

    Example:
        >>> role = Role(name="admin", description="Administrator role")
        >>> print(role.name)
        'admin'
    """

    model_config = ConfigDict(frozen=True)

    id: Optional[str] = Field(default=None, description="Unique identifier for the role")
    name: str = Field(..., description="Human-readable role name")
    description: Optional[str] = Field(default=None, description="Description of the role's purpose")
    composite: bool = Field(default=False, description="Whether this role is composite")
    client_role: bool = Field(default=False, description="Whether this is a client-specific role", alias="clientRole")
    container_id: Optional[str] = Field(
        default=None, description="ID of the container that owns this role", alias="containerId"
    )


class BaseClaims(BaseModel, ABC):
    """JWT token claims using standard OIDC names.

    Represents the payload of a decoded JWT token following OpenID Connect
    standard claims with extensions for role-based access control.

    Attributes:
        iss: Issuer - identifies the provider that issued the token.
        sub: Subject - unique identifier for the user.
        aud: Audience - intended recipient(s) of the token.
        exp: Expiration time - Unix timestamp when token expires.
        iat: Issued at - Unix timestamp when token was created.
        jti: JWT ID - unique identifier for this token.
        typ: Token type - typically "Bearer".
        azp: Authorized party - client that requested the token.
        scope: Space-separated list of OAuth2 scopes.
        email: User's email address.
        email_verified: Whether the email address has been verified.
        preferred_username: User's preferred username.
        realm_access: Keycloak-style realm roles structure.
        resource_access: Keycloak-style client-specific roles structure.

    Example:
        >>> claims = Claims(
        ...     iss="https://auth.example.com",
        ...     sub="user-123",
        ...     aud="my-client",
        ...     exp=1700000000,
        ...     iat=1699996400
        ... )
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    iss: str = Field(..., description="Issuer - identifies the provider that issued the token")
    sub: str = Field(..., description="Subject - unique identifier for the user")
    aud: str = Field(..., description="Audience - intended recipient(s) of the token")
    exp: int = Field(..., description="Expiration time - Unix timestamp when token expires")
    iat: int = Field(..., description="Issued at - Unix timestamp when token was created")
    jti: Optional[str] = Field(default=None, description="JWT ID - unique identifier for this token")
    typ: Optional[str] = Field(default=None, description='Token type - typically "Bearer"')
    azp: Optional[str] = Field(default=None, description="Authorized party - client that requested the token")
    scope: Optional[str] = Field(default=None, description="Space-separated list of OAuth2 scopes")
    email: Optional[str] = Field(default=None, description="User's email address")
    email_verified: Optional[bool] = Field(default=None, description="Whether the email address has been verified")
    preferred_username: Optional[str] = Field(default=None, description="User's preferred username")

    @abstractmethod
    def get_roles(self) -> List[str]:
        """Get roles assigned to the user from the claims.

        Returns:
            List of role names representing the user's roles.

        Example:
            >>> roles = claims.get_roles()
            >>> for role in roles:
            ...     print(role)
        """

    @abstractmethod
    def get_client_roles(self, client_id: str) -> List[str]:
        """Get client-specific roles assigned to the user.

        Args:
            client_id: Client ID to retrieve roles for.

        Returns:
            List of role names for the specified client.

        Example:
            >>> client_roles = claims.get_client_roles("my-client")
            >>> for role in client_roles:
            ...     print(role)
        """

    @abstractmethod
    def get_all_client_roles(self) -> Dict[str, List[str]]:
        """Get all client-specific roles assigned to the user.

        Returns:
            Dictionary mapping client IDs to lists of role names.

        Example:
            >>> all_client_roles = claims.get_all_client_roles()
            >>> for client_id, roles in all_client_roles.items():
            ...     print(f"{client_id}: {roles}")
        """


class Token(BaseModel):
    """Token representation.

    Represents an OAuth2/OIDC token response containing access tokens
    and related metadata.

    Attributes:
        access_token: JWT access token for API authentication.
        refresh_token: Optional token for obtaining new access tokens.
        id_token: Optional OIDC ID token with user identity claims.
        expires_in_seconds: Token lifetime in seconds.
        token_type: Type of token, typically "Bearer".

    Example:
        >>> token = Token(
        ...     access_token="eyJhbGc...",
        ...     expires_in_seconds=3600,
        ...     token_type="Bearer"
        ... )
        >>> print(f"Token expires in {token.expires_in_seconds} seconds")
    """

    model_config = ConfigDict(frozen=True)

    access_token: str = Field(..., description="JWT access token for API authentication", alias="access_token")
    refresh_token: Optional[str] = Field(
        default=None, description="Token for obtaining new access tokens", alias="refresh_token"
    )
    id_token: Optional[str] = Field(
        default=None, description="OIDC ID token with user identity claims", alias="id_token"
    )
    expires_in_seconds: int = Field(..., description="Token lifetime in seconds", alias="expires_in_seconds")
    token_type: str = Field(..., description='Type of token, typically "Bearer"', alias="token_type")


class User(BaseModel):
    """User representation with parsed roles.

    Represents an authenticated user with their identity information and
    assigned roles. Roles are organized by realm (global) and client (application-specific).

    Attributes:
        id: Unique user identifier (typically the 'sub' claim from JWT).
        username: User's username or login name.
        email: User's email address.
        email_verified: Whether the email address has been verified.
        realm_roles: List of realm-level role names (e.g., ["admin", "user"]).
        client_roles: Dictionary mapping client IDs to lists of role names
                     (e.g., {"my-app": ["editor", "viewer"]}).

    Example:
        >>> user = User(
        ...     id="user-123",
        ...     username="john_doe",
        ...     email="john@example.com",
        ...     realm_roles=["user"],
        ...     client_roles={"my-app": ["editor"]}
        ... )
        >>> print(user.realm_roles)
        ['user']
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique user identifier")
    username: Optional[str] = Field(default=None, description="User's username or login name")
    email: Optional[str] = Field(default=None, description="User's email address")
    email_verified: Optional[bool] = Field(default=None, description="Whether the email address has been verified")
    realm_roles: List[str] = Field(default_factory=list, description="List of realm-level role names")
    client_roles: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Dictionary mapping client IDs to lists of role names",
        alias="client_roles",
    )

    @classmethod
    def from_claims(cls, claims: BaseClaims) -> "User":
        """Create User from JWT claims.

        Extracts user information and roles from decoded JWT token claims.

        Args:
            claims: JWT token claims containing user information and roles.

        Returns:
            User object with extracted identity and roles.

        Example:
            >>> claims = Claims(iss="...", sub="user-123", aud="client", exp=123, iat=120)
            >>> user = User.from_claims(claims)
            >>> print(user.id)
            'user-123'
        """

        return cls(
            id=claims.sub,
            username=claims.preferred_username,
            email=claims.email,
            email_verified=claims.email_verified,
            realm_roles=claims.get_roles(),
            client_roles=claims.get_all_client_roles(),
        )

    def has_realm_role(self, role_name: str) -> bool:
        """Check if user has a specific realm role.

        Args:
            role_name: Role name to check (case-sensitive).

        Returns:
            True if user has the role, False otherwise.

        Example:
            >>> if user.has_realm_role("admin"):
            ...     print("User is admin")
        """
        return role_name in self.realm_roles

    def require_realm_role(self, role_name: str) -> None:
        """Require user to have a specific realm role.

        Args:
            role_name: Required role name.

        Raises:
            AuthorizationError: User does not have the required role.

        Example:
            >>> user.require_realm_role("admin")  # Raises if not admin
        """
        if not self.has_realm_role(role_name):
            raise AuthorizationException(
                required_role=role_name,
            )

    def has_client_role(self, client_id: str, role_name: str) -> bool:
        """Check if user has a specific client role.

        Args:
            client_id: Client ID.
            role_name: Role name to check.

        Returns:
            True if user has the role for the client, False otherwise.

        Example:
            >>> if user.has_client_role("my-app", "editor"):
            ...     enable_editing()
        """
        return role_name in self.client_roles.get(client_id, [])

    def require_client_role(self, client_id: str, role_name: str) -> None:
        """Require user to have a specific client role.

        Args:
            client_id: Client ID.
            role_name: Required role name.

        Raises:
            AuthorizationError: User does not have the required role for the client.

        Example:
            >>> user.require_client_role("my-app", "editor")  # Raises if not editor
        """
        if not self.has_client_role(client_id, role_name):
            raise AuthorizationException(
                required_role=f"{client_id}:{role_name}",
            )
