# Implementation Plan: miraveja-authentication

**Complete Reconstruction from Scratch**

Build a production-ready OAuth2/OpenID Connect authentication library following DDD/Hexagonal Architecture, Clean Code principles, and full OOP design.

---

## Core Principles

### 1. Full Object-Oriented Programming

- **No standalone functions** - all functionality encapsulated in classes
- **Behavior with data** - methods belong to the objects they operate on
- **Clear responsibilities** - single responsibility per class
- **Proper encapsulation** - private implementation, public interfaces

### 2. DDD/Hexagonal Architecture

```
Domain (Core Business Logic)
    ↑
Application (Use Cases & Orchestration)
    ↑
Infrastructure (External Integrations)
```

**Layer Separation:**

- **Domain**: Business models (User, Token, Role), interfaces (IOAuth2Provider, IClaimsParser, IOIDCDiscoveryService, IAuthenticator), base claims (BaseClaims), exceptions
- **Application**: Use cases and orchestration
  - `OAuth2Configuration`: Configuration management
  - `OAuth2Provider`: Token validation use case (orchestrates validation flow)
- **Infrastructure**: External integrations
  - **Providers** (per-provider implementations):
    - `keycloak/`: KeycloakClaims, KeycloakClaimsParser, KeycloakOIDCDiscovery
  - **Services**:
    - `OIDCDiscoveryService`: HTTP-based OIDC discovery and JWKS retrieval
  - **FastAPI Integration**: FastAPIAuthenticator
  - **Testing**: MockOAuth2Provider

**Key Design Decisions:**

1. **OAuth2Provider in Application Layer**: Represents a use case (validating tokens) and orchestrates business logic. Depends on `IOIDCDiscoveryService` and `IClaimsParser` (domain interfaces) implemented in infrastructure.

2. **Claims Parser Architecture**:
   - `BaseClaims` (domain): Provider-agnostic OIDC standard claims with abstract methods for role extraction
   - `KeycloakClaims` (infrastructure): Keycloak-specific claims with realm_access/resource_access fields
   - `IClaimsParser` (domain): Interface for parsing raw JWT payload into provider-specific Claims
   - Each Claims class knows how to extract its own roles → eliminates separate role mapper classes

3. **Benefits**:
   - Better encapsulation: Claims contain both data and behavior (role extraction)
   - Type safety: Each provider has properly typed claims structure
   - Extensibility: Easy to add new providers (Auth0, Cognito, etc.) without modifying existing code
   - Cleaner User creation: `User.from_claims(claims)` - no external mapper needed

### 3. Clean Code Standards

- Explicit over implicit
- Readable, self-documenting code
- Comprehensive docstrings (Google style)
- Type hints throughout
- 100% test coverage

### 4. Silent Library

- No logging output
- No print statements
- No unwanted side effects
- Consumers control their own logging

---

## Project Structure

```
miraveja-authentication/
├── pyproject.toml                 # Poetry configuration
├── README.md                      # User documentation
├── .gitignore
├── .pre-commit-config.yaml
│
├── src/
│   └── miraveja_auth/
│       ├── __init__.py            # Public API exports
│       │
│       ├── domain/                # Domain Layer
│       │   ├── __init__.py
│       │   ├── models.py          # User, BaseClaims, Token, Role
│       │   ├── interfaces.py      # IOAuth2Provider, IClaimsParser, IOIDCDiscoveryService, IAuthenticator
│       │   └── exceptions.py      # All custom exceptions
│       │
│       ├── application/           # Application Layer
│       │   ├── __init__.py
│       │   ├── configuration.py   # OAuth2Configuration
│       │   └── oauth2_provider.py # OAuth2Provider (use case)
│       │
│       └── infrastructure/        # Infrastructure Layer
│           ├── __init__.py
│           ├── providers/         # Provider-specific implementations
│           │   ├── __init__.py
│           │   └── keycloak/
│           │       ├── __init__.py
│           │       ├── claims.py          # KeycloakClaims
│           │       ├── parser.py          # KeycloakClaimsParser
│           │       └── discovery.py       # KeycloakOIDCDiscovery (optional)
│           ├── services/
│           │   ├── __init__.py
│           │   └── oidc_discovery.py      # OIDCDiscoveryService (generic)
│           ├── fastapi_integration/
│           │   ├── __init__.py
│           │   └── authenticator.py       # FastAPIAuthenticator
│           └── testing/
│               ├── __init__.py
│               └── mock_provider.py       # MockOAuth2Provider
│
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── domain/
│   │   │   ├── __init__.py
│   │   │   ├── test_models.py
│   │   │   └── test_exceptions.py
│   │   ├── application/
│   │   │   ├── __init__.py
│   │   │   ├── test_configuration.py
│   │   │   └── test_oauth2_provider.py
│   │   └── infrastructure/
│   │       ├── __init__.py
│   │       ├── providers/
│   │       │   ├── __init__.py
│   │       │   └── keycloak/
│   │       │       ├── __init__.py
│   │       │       ├── test_claims.py
│   │       │       └── test_parser.py
│   │       ├── test_oidc_discovery.py
│   │       ├── test_fastapi_authenticator.py
│   │       └── test_mock_provider.py
│   │
│   └── integration/
│       ├── __init__.py
│       ├── test_token_validation.py
│       ├── test_role_authorization.py
│       └── test_fastapi_integration.py
│
└── examples/
    ├── basic_usage.py
    ├── fastapi_app.py
    └── custom_claims_parser.py
```

---

## Implementation Phases

### Phase 1: Project Setup & Domain Layer

**Step 1.1: Initialize Project**

```bash
poetry new miraveja-authentication --name miraveja_auth
cd miraveja-authentication
poetry add pydantic httpx "PyJWT[crypto]"
poetry add --group dev pytest pytest-asyncio pytest-cov black pylint isort mypy pre-commit
poetry add --optional fastapi
```

**Step 1.2: Configure Poetry**

Update `pyproject.toml`:

```toml
[tool.poetry]
name = "miraveja-authentication"
version = "0.1.0"
description = "OAuth2/OpenID Connect authentication library"
authors = ["Jomar Júnior de Souza Pereira <jomarjunior@poli.ufrj.br>"]
readme = "README.md"
packages = [{include = "miraveja_auth", from = "src"}]

[tool.poetry.dependencies]
python = "^3.10"
pydantic = "^2.0"
httpx = "^0.25"
PyJWT = {extras = ["crypto"], version = "^2.8"}
fastapi = {version = "^0.104", optional = true}

[tool.poetry.extras]
fastapi = ["fastapi"]

[tool.poetry.group.dev.dependencies]
pytest = "^7.4"
pytest-asyncio = "^0.21"
pytest-cov = "^4.1"
black = "^23.11"
pylint = "^3.0"
isort = "^5.12"
mypy = "^1.7"
pre-commit = "^3.5"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

**Step 1.3: Create Domain Models**

`src/miraveja_auth/domain/models.py`:

```python
"""Domain models for authentication."""
from abc import ABC, abstractmethod
from typing import Optional, Dict, List
from pydantic import BaseModel, Field


class Role(BaseModel):
    """Role value object."""
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    composite: bool = False
    client_role: bool = Field(default=False, alias="clientRole")
    container_id: Optional[str] = Field(default=None, alias="containerId")


class BaseClaims(BaseModel, ABC):
    """Base JWT token claims (OIDC standard - provider-agnostic).

    This abstract base class defines standard OIDC claims that are common
    across all OAuth2/OIDC providers. Provider-specific claims (e.g., Keycloak,
    Auth0) should inherit from this class and add their custom fields.

    Each concrete Claims class must implement role extraction methods,
    encapsulating the logic for how roles are stored in that provider's tokens.
    """
    # Standard OIDC claims (required)
    iss: str  # Issuer
    sub: str  # Subject (user ID)
    aud: str | List[str]  # Audience
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp

    # Optional standard OIDC claims
    jti: Optional[str] = None
    typ: Optional[str] = None
    azp: Optional[str] = None
    scope: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    preferred_username: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional provider-specific claims

    @abstractmethod
    def get_realm_roles(self) -> List[str]:
        """Extract realm/global roles from claims.

        Returns:
            List of realm role names.
        """
        pass

    @abstractmethod
    def get_client_roles(self, client: Optional[str] = None) -> Dict[str, List[str]]:
        """Extract client-specific roles from claims.

        Args:
            client: Optional client ID. If provided, return roles for that client only.
                   If None, return all client roles.

        Returns:
            Dictionary mapping client IDs to role lists.
        """
        pass


class User(BaseModel):
    """Authenticated user with roles."""
    id: str
    username: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    realm_roles: List[str] = Field(default_factory=list)
    client_roles: Dict[str, List[str]] = Field(default_factory=dict)

    @classmethod
    def from_claims(cls, claims: BaseClaims) -> "User":
        """Create User from JWT claims.

        Claims object knows how to extract its own roles based on provider-specific structure.

        Args:
            claims: Provider-specific claims (inherits from BaseClaims).

        Returns:
            User instance with extracted roles.
        """
        return cls(
            id=claims.sub,
            username=claims.preferred_username,
            email=claims.email,
            email_verified=claims.email_verified or False,
            realm_roles=claims.get_realm_roles(),
            client_roles=claims.get_client_roles(),
        )

    def has_realm_role(self, role: str) -> bool:
        """Check if user has a realm role.

        Args:
            role: Role name (case-sensitive).

        Returns:
            True if user has the role, False otherwise.
        """
        return role in self.realm_roles

    def require_realm_role(self, role: str) -> None:
        """Require user to have a realm role.

        Args:
            role: Required role name.

        Raises:
            AuthorizationError: User doesn't have the role.
        """
        if not self.has_realm_role(role):
            from .exceptions import AuthorizationError
            raise AuthorizationError(
                f"User does not have required realm role: {role}",
                required_role=role
            )

    def has_client_role(self, client: str, role: str) -> bool:
        """Check if user has a client-specific role.

        Args:
            client: Client ID.
            role: Role name (case-sensitive).

        Returns:
            True if user has the role for the client, False otherwise.
        """
        return role in self.client_roles.get(client, [])

    def require_client_role(self, client: str, role: str) -> None:
        """Require user to have a client role.

        Args:
            client: Client ID.
            role: Required role name.

        Raises:
            AuthorizationError: User doesn't have the role.
        """
        if not self.has_client_role(client, role):
            from .exceptions import AuthorizationError
            raise AuthorizationError(
                f"User does not have required client role '{role}' for client '{client}'",
                required_role=f"{client}:{role}"
            )


class Token(BaseModel):
    """OAuth2 token representation."""
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: int
    token_type: str = "Bearer"
```

**Step 1.4: Create Domain Interfaces**

`src/miraveja_auth/domain/interfaces.py`:

```python
"""Domain interfaces."""
from abc import ABC, abstractmethod
from typing import Dict, Any
from .models import User, BaseClaims


class IOAuth2Provider(ABC):
    """OAuth2/OIDC provider interface."""

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
        pass


class IClaimsParser(ABC):
    """Claims parser interface.

    Parses raw JWT payload into provider-specific Claims objects.
    Each provider implementation (Keycloak, Auth0, etc.) provides its own parser.
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
        pass
```

**Step 1.5: Create Domain Exceptions**

`src/miraveja_auth/domain/exceptions.py`:

```python
"""Domain exceptions."""


class AuthenticationError(Exception):
    """Base exception for authentication failures."""

    def __init__(self, message: str, detail: str = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)


class TokenExpiredError(AuthenticationError):
    """Token has expired."""

    def __init__(self, message: str = "Token has expired", expires_at: int = None, ttl: int = None):
        super().__init__(message)
        self.expires_at = expires_at
        self.ttl = ttl


class TokenInvalidError(AuthenticationError):
    """Token signature or structure is invalid."""
    pass


class AuthorizationError(Exception):
    """User lacks required permissions."""

    def __init__(self, message: str, required_role: str = None):
        self.message = message
        self.required_role = required_role
        super().__init__(self.message)


class ConfigurationError(Exception):
    """Invalid configuration."""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")
```

**Step 1.6: Create Domain **init**.py**

`src/miraveja_auth/domain/__init__.py`:

```python
"""Domain layer - Core business logic."""
from .models import User, BaseClaims, Token, Role
from .interfaces import (
    IOAuth2Provider,
    IClaimsParser,
    IOIDCDiscoveryService,
    IAuthenticator,
)
from .exceptions import (
    AuthenticationError,
    TokenExpiredError,
    TokenInvalidError,
    AuthorizationError,
    ConfigurationError,
)

__all__ = [
    "User",
    "BaseClaims",
    "Token",
    "Role",
    "IOAuth2Provider",
    "IClaimsParser",
    "IOIDCDiscoveryService",
    "IAuthenticator",
    "AuthenticationError",
    "TokenExpiredError",
    "TokenInvalidError",
    "AuthorizationError",
    "ConfigurationError",
]
```

---

### Phase 2: Application Layer

**Step 2.1: Create OAuth2Configuration**

`src/miraveja_auth/application/configuration.py`:

```python
"""Application configuration."""
import os
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from ..domain.exceptions import ConfigurationError


class OAuth2Configuration(BaseModel):
    """OAuth2/OIDC provider configuration."""

    issuer: str = Field(..., description="OIDC issuer URL")
    client_id: str = Field(..., description="OAuth2 client ID")
    client_secret: Optional[str] = Field(default=None, description="Client secret")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    public_key: Optional[str] = Field(default=None, description="Static public key")
    token_verification_algorithm: str = Field(default="RS256", description="JWT algorithm")
    token_minimum_ttl: int = Field(default=60, description="Minimum token TTL (seconds)")

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate and normalize issuer URL."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("Issuer must be a valid HTTP(S) URL")
        return v.rstrip("/")

    @classmethod
    def from_env(cls) -> "OAuth2Configuration":
        """Create configuration from environment variables.

        Environment variables:
            OAUTH2_ISSUER: Required
            OAUTH2_CLIENT_ID: Required
            OAUTH2_CLIENT_SECRET: Optional
            OAUTH2_VERIFY_SSL: Optional (default: true)
            OAUTH2_PUBLIC_KEY: Optional
            OAUTH2_TOKEN_ALGORITHM: Optional (default: RS256)
            OAUTH2_TOKEN_MIN_TTL: Optional (default: 60)

        Returns:
            OAuth2Configuration instance.

        Raises:
            ConfigurationError: Required variables missing.
        """
        issuer = os.getenv("OAUTH2_ISSUER")
        if not issuer:
            raise ConfigurationError("OAUTH2_ISSUER", "Environment variable is required")

        client_id = os.getenv("OAUTH2_CLIENT_ID")
        if not client_id:
            raise ConfigurationError("OAUTH2_CLIENT_ID", "Environment variable is required")

        return cls(
            issuer=issuer,
            client_id=client_id,
            client_secret=os.getenv("OAUTH2_CLIENT_SECRET"),
            verify_ssl=os.getenv("OAUTH2_VERIFY_SSL", "true").lower() == "true",
            public_key=os.getenv("OAUTH2_PUBLIC_KEY"),
            token_verification_algorithm=os.getenv("OAUTH2_TOKEN_ALGORITHM", "RS256"),
            token_minimum_ttl=int(os.getenv("OAUTH2_TOKEN_MIN_TTL", "60")),
        )
```

**Step 2.2: Create OAuth2Provider (Use Case)**

`src/miraveja_auth/application/oauth2_provider.py`:

```python
"""OAuth2 provider - Token validation use case."""
import time
import jwt
from .configuration import OAuth2Configuration
from ..domain.interfaces import IOAuth2Provider, IClaimsParser, IOIDCDiscoveryService
from ..domain.models import User
from ..domain.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    AuthenticationError,
)


class OAuth2Provider(IOAuth2Provider):
    """OAuth2/OIDC provider - Token validation use case.

    This class orchestrates token validation by:
    1. Checking token expiration and TTL
    2. Verifying JWT signature (offline with static key or online with JWKS)
    3. Parsing claims using provider-specific parser
    4. Creating User from claims (claims extract their own roles)
    """

    def __init__(
        self,
        config: OAuth2Configuration,
        discovery_service: IOIDCDiscoveryService,
        claims_parser: IClaimsParser,
    ):
        """Initialize provider.

        Args:
            config: OAuth2 configuration.
            discovery_service: Service for OIDC discovery and JWKS.
            claims_parser: Parser for converting JWT payload to provider-specific Claims.
        """
        self._config = config
        self._discovery = discovery_service
        self._claims_parser = claims_parser

    async def validate_token(self, token: str) -> User:
        """Validate JWT token and return authenticated user.

        Args:
            token: JWT access token.

        Returns:
            Authenticated User with roles.

        Raises:
            TokenExpiredError: Token has expired.
            TokenInvalidError: Token is invalid.
            AuthenticationError: Other validation errors.
        """
        try:
            # Decode without verification first to check expiration
            unverified = jwt.decode(
                token,
                options={"verify_signature": False}
            )

            # Check expiration and TTL
            exp = unverified.get("exp", 0)
            current_time = int(time.time())

            if exp <= current_time:
                raise TokenExpiredError(
                    "Token has expired",
                    expires_at=exp,
                    ttl=0
                )

            ttl = exp - current_time
            if ttl < self._config.token_minimum_ttl:
                raise TokenExpiredError(
                    f"Token TTL ({ttl}s) is less than minimum ({self._config.token_minimum_ttl}s)",
                    expires_at=exp,
                    ttl=ttl
                )

            # Verify signature and decode
            if self._config.public_key:
                # Offline validation with static key
                verified_payload = jwt.decode(
                    token,
                    self._config.public_key,
                    algorithms=[self._config.token_verification_algorithm],
                    audience=self._config.client_id,
                    issuer=self._config.issuer,
                )
            else:
                # Online validation with JWKS
                signing_key = await self._discovery.get_signing_key(token)

                verified_payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=[self._config.token_verification_algorithm],
                    audience=self._config.client_id,
                    issuer=self._config.issuer,
                )

            # Parse claims using provider-specific parser
            claims = self._claims_parser.parse(verified_payload)

            # Create user from claims (claims know how to extract roles)
            user = User.from_claims(claims)

            return user

        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token signature has expired")
        except jwt.InvalidTokenError as e:
            raise TokenInvalidError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise AuthenticationError(f"Token validation failed: {str(e)}")
```

**Step 2.3: Create Application **init**.py**

`src/miraveja_auth/application/__init__.py`:

```python
"""Application layer - Use cases and orchestration."""
from .configuration import OAuth2Configuration
from .oauth2_provider import OAuth2Provider

__all__ = ["OAuth2Configuration", "OAuth2Provider"]
```

---

### Phase 3: Infrastructure Layer - Services

**Step 3.1: Create OIDC Discovery Interface**

First, add the interface to domain layer:

`src/miraveja_auth/domain/interfaces.py` (add to existing file):

```python
class IOIDCDiscoveryService(ABC):
    """OIDC discovery and JWKS service interface."""

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
        pass

    @abstractmethod
    async def discover_configuration(self) -> Dict[str, Any]:
        """Fetch OIDC discovery configuration.

        Returns:
            OIDC configuration dictionary.

        Raises:
            AuthenticationError: Discovery failed.
        """
        pass
```

**Step 3.2: Create OIDCDiscoveryService**

`src/miraveja_auth/infrastructure/services/oidc_discovery.py`:

```python
"""OIDC discovery service - External HTTP operations."""
import time
from typing import Dict, Any, Optional
import httpx
from jwt import PyJWKClient
from ...application.configuration import OAuth2Configuration
from ...domain.interfaces import IOIDCDiscoveryService
from ...domain.exceptions import AuthenticationError


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
        self._cache_expiry: float = 0
        self._cache_ttl: int = 3600  # 1 hour

    async def get_signing_key(self, token: str) -> Any:
        """Get signing key for JWT token validation.

        Args:
            token: JWT token to extract key ID from.

        Returns:
            Signing key for verification.

        Raises:
            AuthenticationError: Key retrieval failed.
        """
        await self._ensure_jwks_client()
        return self._jwks_client.get_signing_key_from_jwt(token)

    async def discover_configuration(self) -> Dict[str, Any]:
        """Fetch OIDC discovery configuration.

        Returns:
            OIDC configuration dictionary.

        Raises:
            AuthenticationError: Discovery failed.
        """
        if self._oidc_config:
            return self._oidc_config

        discovery_url = f"{self._config.issuer}/.well-known/openid-configuration"

        async with httpx.AsyncClient(verify=self._config.verify_ssl) as client:
            try:
                response = await client.get(discovery_url)
                response.raise_for_status()
                self._oidc_config = response.json()
                return self._oidc_config
            except Exception as e:
                raise AuthenticationError(f"OIDC discovery failed: {str(e)}")

    async def _ensure_jwks_client(self) -> None:
        """Ensure JWKS client is initialized and cache is valid."""
        if self._jwks_client and time.time() < self._cache_expiry:
            return

        if not self._oidc_config:
            self._oidc_config = await self.discover_configuration()

        if not self._jwks_uri:
            self._jwks_uri = self._oidc_config.get("jwks_uri")
            if not self._jwks_uri:
                raise AuthenticationError("No jwks_uri in OIDC configuration")

        self._jwks_client = PyJWKClient(self._jwks_uri)
        self._cache_expiry = time.time() + self._cache_ttl
```

**Step 3.3: Create Keycloak Provider - Claims**

`src/miraveja_auth/infrastructure/providers/keycloak/claims.py`:

```python
"""Keycloak-specific JWT claims."""
from typing import List, Dict, Optional
from ....domain.models import BaseClaims


class KeycloakClaims(BaseClaims):
    """Keycloak-specific JWT token claims.

    Extends BaseClaims with Keycloak's custom claim structure for roles:
    - realm_access: Contains realm-level roles
    - resource_access: Contains client-specific roles
    """

    # Keycloak-specific fields
    realm_access: Optional[Dict[str, List[str]]] = None
    resource_access: Optional[Dict[str, Dict[str, List[str]]]] = None

    def get_realm_roles(self) -> List[str]:
        """Extract realm roles from Keycloak claims structure.

        Keycloak stores realm roles in: realm_access.roles[]

        Returns:
            List of realm role names.
        """
        if not self.realm_access:
            return []
        return self.realm_access.get("roles", [])

    def get_client_roles(self, client: Optional[str] = None) -> Dict[str, List[str]]:
        """Extract client-specific roles from Keycloak claims.

        Keycloak stores client roles in: resource_access.<client>.roles[]

        Args:
            client: Optional client ID. If provided, return roles for that client only.
                   If None, return all client roles.

        Returns:
            Dictionary mapping client IDs to role lists.
        """
        if not self.resource_access:
            return {}

        if client:
            # Return roles for specific client
            client_access = self.resource_access.get(client, {})
            roles = client_access.get("roles", [])
            return {client: roles} if roles else {}

        # Return all client roles
        result = {}
        for client_id, access in self.resource_access.items():
            roles = access.get("roles", [])
            if roles:
                result[client_id] = roles
        return result
```

**Step 3.4: Create Keycloak Provider - Parser**

`src/miraveja_auth/infrastructure/providers/keycloak/parser.py`:

```python
"""Keycloak claims parser."""
from typing import Dict, Any
from ....domain.interfaces import IClaimsParser
from ....domain.exceptions import TokenInvalidError
from .claims import KeycloakClaims


class KeycloakClaimsParser(IClaimsParser):
    """Parser for Keycloak JWT payloads.

    Converts raw JWT payload dictionaries into KeycloakClaims objects.
    """

    def parse(self, payload: Dict[str, Any]) -> KeycloakClaims:
        """Parse JWT payload into KeycloakClaims.

        Args:
            payload: Raw JWT token payload (decoded dict).

        Returns:
            KeycloakClaims instance.

        Raises:
            TokenInvalidError: Payload structure is invalid.
        """
        try:
            return KeycloakClaims(**payload)
        except Exception as e:
            raise TokenInvalidError(f"Failed to parse Keycloak claims: {str(e)}")
```

**Step 3.5: Create Keycloak Provider **init**.py**

`src/miraveja_auth/infrastructure/providers/keycloak/__init__.py`:

```python
"""Keycloak provider implementation."""
from .claims import KeycloakClaims
from .parser import KeycloakClaimsParser

__all__ = ["KeycloakClaims", "KeycloakClaimsParser"]
```

**Step 3.6: Create providers **init**.py**

`src/miraveja_auth/infrastructure/providers/__init__.py`:

```python
"""Provider-specific implementations."""
from .keycloak import KeycloakClaims, KeycloakClaimsParser

__all__ = ["KeycloakClaims", "KeycloakClaimsParser"]
```

**Step 3.7: Create services **init**.py**

`src/miraveja_auth/infrastructure/services/__init__.py`:

```python
"""Infrastructure services."""
from .oidc_discovery import OIDCDiscoveryService

__all__ = ["OIDCDiscoveryService"]
```

---

### Phase 4: Infrastructure Layer - FastAPI Integration

**Step 4.1: Create IAuthenticator Interface**

First, add the interface to domain layer:

`src/miraveja_auth/domain/interfaces.py` (add to existing file):

```python
class IAuthenticator(ABC):
    """Authenticator interface for dependency injection frameworks."""

    @abstractmethod
    async def get_current_user(self, *args, **kwargs) -> User:
        """Get current authenticated user (required).

        Returns:
            Authenticated User.

        Raises:
            Framework-specific exception if authentication fails.
        """
        pass

    @abstractmethod
    async def get_current_user_optional(self, *args, **kwargs) -> Optional[User]:
        """Get current user (optional authentication).

        Returns:
            Authenticated User or None.
        """
        pass

    @abstractmethod
    def require_realm_role(self, role: str) -> Any:
        """Create dependency requiring a realm role.

        Args:
            role: Required realm role name.

        Returns:
            Framework-specific dependency.
        """
        pass

    @abstractmethod
    def require_client_role(self, client: str, role: str) -> Any:
        """Create dependency requiring a client role.

        Args:
            client: Client ID.
            role: Required client role name.

        Returns:
            Framework-specific dependency.
        """
        pass
```

**Step 4.2: Create Base FastAPI Authenticator**

`src/miraveja_auth/infrastructure/fastapi_integration/base.py`:

```python
"""Base FastAPI authenticator."""
from typing import Callable
from fastapi import Depends, HTTPException, status
from ...domain.interfaces import IAuthenticator, IOAuth2Provider
from ...domain.models import User
from ...domain.exceptions import AuthenticationError, AuthorizationError


class BaseFastAPIAuthenticator(IAuthenticator):
    """Base class for FastAPI authenticators.

    Provides common role validation logic.
    """

    def __init__(self, provider: IOAuth2Provider):
        """Initialize authenticator.

        Args:
            provider: OAuth2 provider for token validation.
        """
        self._provider = provider

    async def _validate_token(self, token: str) -> User:
        """Validate token and return user.

        Args:
            token: JWT access token.

        Returns:
            Authenticated User.

        Raises:
            HTTPException: 401 if validation fails.
        """
        try:
            return await self._provider.validate_token(token)
        except AuthenticationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=e.message,
                headers={"WWW-Authenticate": "Bearer"},
            )

    def _create_role_dependency(
        self,
        get_user_func: Callable,
        check_role_func: Callable[[User], None],
    ) -> Callable:
        """Create a role-checking dependency.

        Args:
            get_user_func: Function to get current user.
            check_role_func: Function to check if user has required role.

        Returns:
            FastAPI dependency function.
        """
        async def dependency(user: User = Depends(get_user_func)) -> User:
            try:
                check_role_func(user)
                return user
            except AuthorizationError as e:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=e.message,
                )

        return dependency

    def require_realm_role(self, role: str) -> Callable:
        """Create dependency requiring a realm role.

        Args:
            role: Required realm role name.

        Returns:
            FastAPI dependency function.
        """
        return self._create_role_dependency(
            self.get_current_user,
            lambda user: user.require_realm_role(role),
        )

    def require_client_role(self, client: str, role: str) -> Callable:
        """Create dependency requiring a client role.

        Args:
            client: Client ID.
            role: Required client role name.

        Returns:
            FastAPI dependency function.
        """
        return self._create_role_dependency(
            self.get_current_user,
            lambda user: user.require_client_role(client, role),
        )
```

**Step 4.3: Create HTTP Authenticator**

`src/miraveja_auth/infrastructure/fastapi_integration/http_authenticator.py`:

```python
"""HTTP-based FastAPI authenticator."""
from typing import Optional
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ...domain.models import User
from .base import BaseFastAPIAuthenticator


class HTTPAuthenticator(BaseFastAPIAuthenticator):
    """HTTP Bearer token authenticator for FastAPI.

    Extracts JWT tokens from Authorization header (Bearer scheme).
    Use for standard HTTP REST endpoints.
    """

    def __init__(self, provider):
        """Initialize HTTP authenticator.

        Args:
            provider: OAuth2 provider for token validation.
        """
        super().__init__(provider)
        self._http_bearer = HTTPBearer()
        self._http_bearer_optional = HTTPBearer(auto_error=False)

    async def get_current_user(
        self,
        credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    ) -> User:
        """Get current authenticated user from HTTP Authorization header.

        FastAPI dependency for protected endpoints.

        Args:
            credentials: HTTP Bearer credentials from Authorization header.

        Returns:
            Authenticated User.

        Raises:
            HTTPException: 401 if authentication fails.
        """
        return await self._validate_token(credentials.credentials)

    async def get_current_user_optional(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    ) -> Optional[User]:
        """Get current user from HTTP Authorization header (optional).

        FastAPI dependency for endpoints with optional authentication.

        Args:
            credentials: Optional HTTP Bearer credentials.

        Returns:
            Authenticated User or None.
        """
        if credentials is None:
            return None

        return await self._validate_token(credentials.credentials)
```

**Step 4.4: Create WebSocket Authenticator**

`src/miraveja_auth/infrastructure/fastapi_integration/websocket_authenticator.py`:

```python
"""WebSocket-based FastAPI authenticator."""
from typing import Optional
from fastapi import Query
from ...domain.models import User
from .base import BaseFastAPIAuthenticator


class WebSocketAuthenticator(BaseFastAPIAuthenticator):
    """WebSocket query parameter authenticator for FastAPI.

    Extracts JWT tokens from query string (?token=...).
    Use for WebSocket connections where Authorization headers aren't available.
    """

    async def get_current_user(
        self,
        token: str = Query(..., description="JWT access token"),
    ) -> User:
        """Get current user from WebSocket query parameter.

        FastAPI dependency for protected WebSocket endpoints.

        Args:
            token: JWT token from query string.

        Returns:
            Authenticated User.

        Raises:
            HTTPException: 401 if authentication fails.
        """
        return await self._validate_token(token)

    async def get_current_user_optional(
        self,
        token: Optional[str] = Query(None, description="JWT access token"),
    ) -> Optional[User]:
        """Get current user from WebSocket query parameter (optional).

        FastAPI dependency for WebSocket endpoints with optional auth.

        Args:
            token: Optional JWT token from query string.

        Returns:
            Authenticated User or None.
        """
        if token is None:
            return None

        return await self._validate_token(token)
```

**Step 4.5: Create Unified Authenticator (Convenience)**

`src/miraveja_auth/infrastructure/fastapi_integration/authenticator.py`:

```python
"""Unified FastAPI authenticator with both HTTP and WebSocket support."""
from ...domain.interfaces import IOAuth2Provider
from .http_authenticator import HTTPAuthenticator
from .websocket_authenticator import WebSocketAuthenticator


class FastAPIAuthenticator:
    """Unified authenticator with both HTTP and WebSocket support.

    Convenience class that provides access to both HTTP and WebSocket
    authenticators through a single instance.

    Example:
        authenticator = FastAPIAuthenticator(provider)

        # HTTP endpoints
        @app.get("/profile")
        async def profile(user = Depends(authenticator.http.get_current_user)):
            return {"id": user.id}

        # WebSocket endpoints
        @app.websocket("/ws")
        async def websocket(
            websocket: WebSocket,
            user = Depends(authenticator.ws.get_current_user)
        ):
            await websocket.accept()
            ...
    """

    def __init__(self, provider: IOAuth2Provider):
        """Initialize unified authenticator.

        Args:
            provider: OAuth2 provider for token validation.
        """
        self._http = HTTPAuthenticator(provider)
        self._ws = WebSocketAuthenticator(provider)

    @property
    def http(self) -> HTTPAuthenticator:
        """Get HTTP authenticator."""
        return self._http

    @property
    def ws(self) -> WebSocketAuthenticator:
        """Get WebSocket authenticator."""
        return self._ws

    # Convenience methods - delegate to HTTP authenticator by default

    async def get_current_user(self, *args, **kwargs):
        """Convenience: delegate to HTTP authenticator."""
        return await self._http.get_current_user(*args, **kwargs)

    async def get_current_user_optional(self, *args, **kwargs):
        """Convenience: delegate to HTTP authenticator."""
        return await self._http.get_current_user_optional(*args, **kwargs)

    def require_realm_role(self, role: str):
        """Convenience: delegate to HTTP authenticator."""
        return self._http.require_realm_role(role)

    def require_client_role(self, client: str, role: str):
        """Convenience: delegate to HTTP authenticator."""
        return self._http.require_client_role(client, role)
```

**Step 4.6: Create fastapi_integration **init**.py**

`src/miraveja_auth/infrastructure/fastapi_integration/__init__.py`:

```python
"""FastAPI integration."""
from .base import BaseFastAPIAuthenticator
from .http_authenticator import HTTPAuthenticator
from .websocket_authenticator import WebSocketAuthenticator
from .authenticator import FastAPIAuthenticator

__all__ = [
    "BaseFastAPIAuthenticator",
    "HTTPAuthenticator",
    "WebSocketAuthenticator",
    "FastAPIAuthenticator",
]
```

---

### Phase 5: Infrastructure Layer - Testing Utilities

**Step 5.1: Create MockOAuth2Provider**

`src/miraveja_auth/infrastructure/testing/mock_provider.py`:

```python
"""Mock OAuth2 provider for testing."""
import time
from typing import Optional, Dict
import jwt
from ...domain.interfaces import IOAuth2Provider
from ...domain.models import User
from ...domain.exceptions import TokenExpiredError, TokenInvalidError


class MockOAuth2Provider(IOAuth2Provider):
    """Mock OAuth2 provider for testing."""

    def __init__(self):
        """Initialize mock provider."""
        self._users: Dict[str, User] = {}
        self._tokens: Dict[str, str] = {}  # token -> user_id
        self._failure_mode: Optional[str] = None

    def add_user(
        self,
        user_id: str,
        username: str = None,
        email: str = None,
        realm_roles: list = None,
        client_roles: dict = None,
    ) -> None:
        """Add a test user.

        Args:
            user_id: User ID.
            username: Username (defaults to user_id).
            email: Email address.
            realm_roles: List of realm role names.
            client_roles: Dict of client ID -> role list.
        """
        user = User(
            id=user_id,
            username=username or user_id,
            email=email,
            realm_roles=realm_roles or [],
            client_roles=client_roles or {},
        )
        self._users[user_id] = user

    def set_token_for_user(self, user_id: str, token: str = None) -> str:
        """Map a token to a user.

        Args:
            user_id: User ID to map token to.
            token: Token string (generated if not provided).

        Returns:
            Token string.
        """
        if token is None:
            token = f"mock-token-{user_id}-{int(time.time())}"

        self._tokens[token] = user_id
        return token

    def simulate_failure(self, mode: str) -> None:
        """Simulate authentication failures.

        Args:
            mode: Failure mode ('expired', 'invalid', or None to clear).
        """
        self._failure_mode = mode

    async def validate_token(self, token: str) -> User:
        """Validate mock token and return user.

        Args:
            token: Token string.

        Returns:
            Mocked User.

        Raises:
            TokenExpiredError: If failure mode is 'expired'.
            TokenInvalidError: If failure mode is 'invalid' or token not found.
        """
        if self._failure_mode == "expired":
            raise TokenExpiredError("Simulated token expiration")

        if self._failure_mode == "invalid":
            raise TokenInvalidError("Simulated invalid token")

        user_id = self._tokens.get(token)
        if not user_id:
            raise TokenInvalidError(f"Unknown token: {token}")

        user = self._users.get(user_id)
        if not user:
            raise TokenInvalidError(f"User not found: {user_id}")

        return user
```

**Step 5.2: Create testing **init**.py**

`src/miraveja_auth/infrastructure/testing/__init__.py`:

```python
"""Testing utilities."""
from .mock_provider import MockOAuth2Provider

__all__ = ["MockOAuth2Provider"]
```

---

### Phase 6: Public API & Package Configuration

**Step 6.1: Create Infrastructure **init**.py**

`src/miraveja_auth/infrastructure/__init__.py`:

```python
"""Infrastructure layer - External integrations."""
from .services import OIDCDiscoveryService
from .providers import KeycloakClaims, KeycloakClaimsParser
from .testing import MockOAuth2Provider

__all__ = [
    "OIDCDiscoveryService",
    "KeycloakClaims",
    "KeycloakClaimsParser",
    "MockOAuth2Provider",
]

# FastAPI integration (optional)
try:
    from .fastapi_integration import (
        HTTPAuthenticator,
        WebSocketAuthenticator,
        FastAPIAuthenticator,
    )
    __all__.extend(["HTTPAuthenticator", "WebSocketAuthenticator", "FastAPIAuthenticator"])
except ImportError:
    pass  # FastAPI not installed
```

**Step 6.2: Create Main **init**.py**

`src/miraveja_auth/__init__.py`:

```python
"""miraveja-authentication - OAuth2/OIDC authentication library.

Public API exports.
"""

__version__ = "0.1.0"

# Domain exports
from .domain import (
    User,
    BaseClaims,
    Token,
    Role,
    IOAuth2Provider,
    IClaimsParser,
    IOIDCDiscoveryService,
    IAuthenticator,
    AuthenticationError,
    TokenExpiredError,
    TokenInvalidError,
    AuthorizationError,
    ConfigurationError,
)

# Application exports
from .application import OAuth2Configuration, OAuth2Provider

# Infrastructure exports
from .infrastructure import (
    OIDCDiscoveryService,
    KeycloakClaims,
    KeycloakClaimsParser,
    MockOAuth2Provider,
)

__all__ = [
    # Version
    "__version__",
    # Domain
    "User",
    "BaseClaims",
    "Token",
    "Role",
    "IOAuth2Provider",
    "IClaimsParser",
    "IOIDCDiscoveryService",
    "IAuthenticator",
    "AuthenticationError",
    "TokenExpiredError",
    "TokenInvalidError",
    "AuthorizationError",
    "ConfigurationError",
    # Application
    "OAuth2Configuration",
    "OAuth2Provider",
    # Infrastructure
    "OIDCDiscoveryService",
    "KeycloakClaims",
    "KeycloakClaimsParser",
    "MockOAuth2Provider",
]

# FastAPI integration (conditional)
try:
    from .infrastructure import (
        HTTPAuthenticator,
        WebSocketAuthenticator,
        FastAPIAuthenticator,
    )
    __all__.extend(["HTTPAuthenticator", "WebSocketAuthenticator", "FastAPIAuthenticator"])
except ImportError:
    pass  # FastAPI not installed
```

---

### Phase 7: Testing

**Step 7.1: Unit Tests - Domain**

Create comprehensive tests for:

- `test_models.py`: User role methods, Claims parsing, model validation
- `test_exceptions.py`: Exception creation and attributes

**Step 7.2: Unit Tests - Application**

Create tests for:

- `test_configuration.py`: Configuration validation, from_env() method
- `test_oauth2_provider.py`: Token validation flow, role mapper integration

**Step 7.3: Unit Tests - Infrastructure**

Create tests for:

- `test_oidc_discovery.py`: OIDC discovery, JWKS retrieval, caching
- `test_keycloak_role_mapper.py`: Role extraction from various claim structures
- `test_http_authenticator.py`: HTTP Bearer token extraction, validation
- `test_websocket_authenticator.py`: WebSocket query parameter extraction
- `test_fastapi_authenticator.py`: Unified authenticator, both HTTP and WS
- `test_mock_provider.py`: Mock provider behavior, failure simulation

**Step 7.4: Integration Tests**

Create end-to-end tests for:

- `test_token_validation.py`: Full validation flow
- `test_role_authorization.py`: Role checking and enforcement
- `test_fastapi_integration.py`: FastAPI app with authentication

**Target: 100% test coverage**

---

### Phase 8: Examples & Documentation

**Step 8.1: Create Examples**

`examples/basic_usage.py`:

```python
"""Basic usage example."""
import asyncio
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    KeycloakClaimsParser,
)


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

    # Require role (raises AuthorizationError if missing)
    user.require_realm_role("user")


if __name__ == "__main__":
    asyncio.run(main())
```

`examples/fastapi_app.py`:

```python
"""FastAPI application example."""
from fastapi import FastAPI, Depends, WebSocket
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    KeycloakClaimsParser,
)
from miraveja_auth.infrastructure import FastAPIAuthenticator
from miraveja_auth.domain import User

app = FastAPI()

# Setup authentication
config = OAuth2Configuration.from_env()
discovery = OIDCDiscoveryService(config)
parser = KeycloakClaimsParser()
provider = OAuth2Provider(config, discovery, parser)
authenticator = FastAPIAuthenticator(provider)


@app.get("/")
async def root():
    return {"message": "Public endpoint"}


# HTTP endpoints - use .http or default methods
@app.get("/profile")
async def profile(user: User = Depends(authenticator.get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "roles": user.realm_roles,
    }


@app.get("/admin")
async def admin(user: User = Depends(authenticator.require_realm_role("admin"))):
    return {"message": f"Hello admin {user.username}"}


# WebSocket endpoint - use .ws
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    user: User = Depends(authenticator.ws.get_current_user)
):
    await websocket.accept()
    await websocket.send_json({"message": f"Connected as {user.username}"})
    # ... handle WebSocket communication
```

`examples/custom_claims_parser.py`:

```python
"""Custom claims parser example for Auth0.

This example shows how to create a custom Claims class and parser
for Auth0 (or any other OAuth2/OIDC provider).
"""
from typing import List, Dict, Optional, Any
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    BaseClaims,
    IClaimsParser,
)
from miraveja_auth.domain.exceptions import TokenInvalidError


class Auth0Claims(BaseClaims):
    """Auth0-specific JWT token claims.

    Auth0 stores roles/permissions differently than Keycloak.
    Typically uses custom namespace claims.
    """
    # Auth0-specific fields
    permissions: Optional[List[str]] = None  # Auth0 permissions

    # Custom namespace (configure based on your Auth0 setup)
    # e.g., "https://myapp.com/roles"

    def get_realm_roles(self) -> List[str]:
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

    def get_client_roles(self, client: Optional[str] = None) -> Dict[str, List[str]]:
        """Extract client roles from Auth0 claims.

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
            TokenInvalidError: Payload structure is invalid.
        """
        try:
            return Auth0Claims(**payload)
        except Exception as e:
            raise TokenInvalidError(f"Failed to parse Auth0 claims: {str(e)}")


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
```

`examples/separate_authenticators.py`:

```python
"""Using separate HTTP and WebSocket authenticators."""
from fastapi import FastAPI, Depends, WebSocket
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    KeycloakClaimsParser,
)
from miraveja_auth.infrastructure import HTTPAuthenticator, WebSocketAuthenticator
from miraveja_auth.domain import User

app = FastAPI()

# Setup
config = OAuth2Configuration.from_env()
discovery = OIDCDiscoveryService(config)
parser = KeycloakClaimsParser()
provider = OAuth2Provider(config, discovery, parser)

# Create separate authenticators
http_auth = HTTPAuthenticator(provider)
ws_auth = WebSocketAuthenticator(provider)


# HTTP endpoints
@app.get("/api/profile")
async def http_profile(user: User = Depends(http_auth.get_current_user)):
    return {"id": user.id, "username": user.username}


@app.get("/api/admin")
async def http_admin(user: User = Depends(http_auth.require_realm_role("admin"))):
    return {"message": f"Admin: {user.username}"}


# WebSocket endpoint
@app.websocket("/ws/notifications")
async def ws_notifications(
    websocket: WebSocket,
    user: User = Depends(ws_auth.get_current_user)
):
    await websocket.accept()
    await websocket.send_json({
        "type": "connected",
        "user": user.username,
        "roles": user.realm_roles
    })

    # WebSocket communication loop
    while True:
        data = await websocket.receive_text()
        await websocket.send_json({"echo": data})


# Optional authentication endpoint
@app.get("/api/public")
async def public_optional(user: User = Depends(http_auth.get_current_user_optional)):
    if user:
        return {"message": f"Hello, {user.username}!"}
    return {"message": "Hello, anonymous user!"}
```

**Step 8.2: Create README.md**

(Use the README.md we created earlier, ensuring it reflects the OOP design)

---

### Phase 9: Pre-commit & CI/CD

**Step 9.1: Setup pre-commit**

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.11.0
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/pylint
    rev: v3.0.0
    hooks:
      - id: pylint
        args: [--rcfile=pyproject.toml]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.0
    hooks:
      - id: mypy
        additional_dependencies: [pydantic, types-jwt]
```

**Step 9.2: Setup GitHub Actions**

`.github/workflows/ci.yml`:

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install Poetry
        run: pip install poetry

      - name: Install dependencies
        run: poetry install

      - name: Run tests
        run: poetry run pytest --cov=src/miraveja_auth --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

---

## Implementation Checklist

### Domain Layer

- [ ] Create models.py (User, BaseClaims, Token, Role)
- [ ] Create interfaces.py (IOAuth2Provider, IClaimsParser, IOIDCDiscoveryService, IAuthenticator)
- [ ] Create exceptions.py (all custom exceptions)
- [ ] Write unit tests for domain layer
- [ ] Verify 100% domain coverage

### Application Layer

- [ ] Create configuration.py (OAuth2Configuration)
- [ ] Write unit tests for configuration
- [ ] Test from_env() method

### Application Layer (continued)

- [ ] Create OAuth2Provider (use case with claims_parser parameter)
- [ ] Write unit tests for OAuth2Provider
- [ ] Test token validation flow with claims parser

### Infrastructure Layer - Services

- [ ] Create IOIDCDiscoveryService interface (domain)
- [ ] Create IAuthenticator interface (domain)
- [ ] Create OIDCDiscoveryService (generic)
- [ ] Write unit tests for OIDCDiscoveryService

### Infrastructure Layer - Keycloak Provider

- [ ] Create KeycloakClaims (extends BaseClaims)
- [ ] Implement get_realm_roles() and get_client_roles()
- [ ] Create KeycloakClaimsParser (implements IClaimsParser)
- [ ] Write unit tests for KeycloakClaims
- [ ] Write unit tests for KeycloakClaimsParser

### Infrastructure Layer - FastAPI Integration

- [ ] Create BaseFastAPIAuthenticator
- [ ] Create HTTPAuthenticator
- [ ] Create WebSocketAuthenticator
- [ ] Create FastAPIAuthenticator (unified)
- [ ] Write unit tests for authenticators

### Infrastructure Layer - Testing

- [ ] Create MockOAuth2Provider
- [ ] Write unit tests for mock provider
- [ ] Verify 100% infrastructure coverage

### Integration

- [ ] Write integration tests (OAuth2Provider + KeycloakClaimsParser)
- [ ] Test end-to-end token validation flow
- [ ] Test FastAPI integration with Keycloak
- [ ] Test role extraction from Keycloak tokens

### Documentation

- [ ] Create basic_usage.py example
- [ ] Create fastapi_app.py example
- [ ] Create custom_claims_parser.py example (Auth0)
- [ ] Create separate_authenticators.py example
- [ ] Write comprehensive README
- [ ] Add inline documentation
- [ ] Create API reference

### Quality Assurance

- [ ] Setup pre-commit hooks
- [ ] Configure GitHub Actions
- [ ] Achieve 100% test coverage
- [ ] Pass all linters
- [ ] Pass type checking

---

## Success Criteria

✅ **Code Quality**

- 100% test coverage
- All tests passing
- No linting errors
- Full type hint coverage
- Google-style docstrings

✅ **Architecture**

- Clear separation of layers
- No circular dependencies
- Proper encapsulation
- Full OOP (no loose functions)

✅ **Functionality**

- Token validation working
- Role checking working
- FastAPI integration working
- Mock provider for testing
- Works with multiple providers

✅ **Documentation**

- Comprehensive README
- Working examples
- Clear API documentation
- Architecture explanation

✅ **Developer Experience**

- Easy to install
- Simple API
- Clear error messages
- Good TypeScript-like intellisense

---

## Notes

1. **No Loose Functions**: Everything is a class method or property
2. **Silent Library**: No print() or logging.* calls in production code
3. **Async First**: All I/O operations are async
4. **Type Safe**: Complete type hints for IDE support
5. **Provider Agnostic**: Works with any OAuth2/OIDC compliant provider via IClaimsParser interface
6. **Extensible**: Easy to add new providers (create Claims + Parser classes in infrastructure/providers)
7. **Self-Extracting Claims**: Each Claims class knows how to extract its own roles (no separate mapper needed)
8. **Clean Architecture**: Provider-specific code isolated in infrastructure/providers/\{provider\}/
9. **Testable**: Mock provider included, 100% coverage achievable
