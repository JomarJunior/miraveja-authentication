# 🔐 miraveja-authentication

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#-development-status)
[![Coverage](https://codecov.io/gh/JomarJunior/miraveja-authentication/branch/main/graph/badge.svg)](https://codecov.io/gh/JomarJunior/miraveja-authentication)
[![CI](https://github.com/JomarJunior/miraveja-authentication/actions/workflows/ci.yml/badge.svg)](https://github.com/JomarJunior/miraveja-authentication/actions)

> A lightweight OAuth2/OpenID Connect authentication library for Python with JWT validation and role-based authorization

**Etymology**: Combining "authentication" with the Miraveja ecosystem naming convention

## 🚀 Overview

miraveja-authentication is a modern authentication library that implements OAuth2/OpenID Connect standards with JWT token validation and role-based authorization. Built with DDD/Hexagonal Architecture principles, it provides a clean, protocol-based interface that works with any compliant OAuth2/OIDC provider (Keycloak, Auth0, AWS Cognito, Azure AD, Google, Okta).

Part of the **Miraveja** ecosystem, miraveja-authentication provides authentication and authorization infrastructure for all ecosystem services.

## ✨ Key Features

- 🔑 **OAuth2/OIDC Protocol** - Standards-compliant implementation working with all OAuth2/OIDC providers
- 🎫 **JWT Token Validation** - Signature verification using JWKS (JSON Web Key Sets)
- 🔄 **Automatic OIDC Discovery** - Auto-configuration via `.well-known/openid-configuration`
- 👥 **Role-Based Authorization** - Keycloak-style realm and client roles with extensible mappers
- ⚡ **FastAPI Integration** - First-class support with dependency injection helpers
- 🧪 **Testing Utilities** - Built-in mock providers for unit and integration testing
- 🏗️ **Clean Architecture** - Organized following DDD/Hexagonal Architecture principles

## 🛠️ Technology Stack

### 🐍 Core Runtime

- **Python 3.10+** - Type hints and modern Python features
- **pydantic** - Configuration validation and data modeling
- **httpx** - Async HTTP client for OIDC discovery and JWKS fetching
- **PyJWT[crypto]** - JWT token validation and signature verification

### 🌐 Optional Integrations

- **FastAPI** - Web framework integration

### 🧪 Development

- **pytest** - Testing framework with async support
- **pytest-asyncio** - Async testing utilities
- **pytest-cov** - Coverage reporting
- **black** - Code formatter
- **pylint** - Code quality checker
- **isort** - Import statement organizer
- **mypy** - Static type checker
- **pre-commit** - Git hook framework for automated checks

## 🏛️ Architecture

miraveja-authentication follows Domain-Driven Design and Hexagonal Architecture principles:

```text
src/miraveja_auth/
├── 🧠 domain/           # Core business logic
│                      # - Models: User, Claims, Token, Role
│                      # - Interfaces: IOAuth2Provider, IRoleMapper, IOIDCDiscoveryService, IAuthenticator
│                      # - Exceptions: AuthenticationError, AuthorizationError, etc.
├── 🎬 application/      # Use cases and orchestration
│                      # - OAuth2Configuration: Config validation and management
│                      # - OAuth2Provider: Token validation use case
└── 🔌 infrastructure/   # External integrations
                       # - OIDCDiscoveryService: HTTP-based OIDC discovery and JWKS
                       # - KeycloakRoleMapper: Keycloak role extraction
                       # - FastAPI authenticators: HTTP, WebSocket, unified
                       # - MockOAuth2Provider: Testing utilities
```

**Dependency Rule**: Domain ← Application ← Infrastructure

- **Domain** has no dependencies on other layers
- **Application** depends only on Domain
- **Infrastructure** depends on Application and Domain

## 🎯 Getting Started

### 📋 Prerequisites

- Python 3.10+
- Poetry 2.0+ (recommended) or pip

### 🚀 Installation

```bash
poetry add miraveja-authentication
```

Or with pip:

```bash
pip install miraveja-authentication
```

For FastAPI integration:

```bash
poetry add miraveja-authentication[fastapi]
```

## 📖 Quick Start

### Basic Token Validation

```python
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
)

# Configure OAuth2/OIDC provider
config = OAuth2Configuration(
    issuer="https://your-keycloak.com/realms/myrealm",
    client_id="my-client",
    client_secret="your-secret",
)

# Create discovery service and provider
discovery = OIDCDiscoveryService(config)
provider = OAuth2Provider(config, discovery)

# Validate token
async def authenticate_user(token: str):
    user = await provider.validate_token(token)
    print(f"User ID: {user.id}")
    print(f"Username: {user.username}")
    print(f"Email: {user.email}")
    print(f"Realm Roles: {user.realm_roles}")
    print(f"Client Roles: {user.client_roles}")
```

### Environment-Based Configuration

```python
import os
from miraveja_auth import OAuth2Configuration, OAuth2Provider

# Set environment variables
os.environ["OAUTH2_ISSUER"] = "https://your-keycloak.com/realms/myrealm"
os.environ["OAUTH2_CLIENT_ID"] = "my-client"
os.environ["OAUTH2_CLIENT_SECRET"] = "your-secret"

# Load configuration from environment
config = OAuth2Configuration.from_env()
discovery = OIDCDiscoveryService(config)
provider = OAuth2Provider(config, discovery)
```

### Role-Based Authorization

```python
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    AuthorizationError,
)

async def process_admin_action(token: str):
    discovery = OIDCDiscoveryService(config)
    provider = OAuth2Provider(config, discovery)
    user = await provider.validate_token(token)

    # Check role (returns bool)
    if user.has_realm_role("admin"):
        print("User is admin")

    # Require role (raises AuthorizationError if missing)
    try:
        user.require_realm_role("admin")
        # Proceed with admin action
    except AuthorizationError as e:
        print(f"Access denied: {e}")
```

### Client-Specific Roles

```python
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
)

async def process_api_request(token: str):
    discovery = OIDCDiscoveryService(config)
    provider = OAuth2Provider(config, discovery)
    user = await provider.validate_token(token)

    # Check client-specific role
    if user.has_client_role("api-client", "read:documents"):
        # User has read:documents role for api-client
        pass

    # Require client role
    user.require_client_role("api-client", "write:documents")
```

## ⚡ FastAPI Integration

### Basic Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
)
from miraveja_auth.infrastructure import FastAPIAuthenticator

app = FastAPI()

# Configure authentication
config = OAuth2Configuration.from_env()
discovery = OIDCDiscoveryService(config)
provider = OAuth2Provider(config, discovery)
authenticator = FastAPIAuthenticator(provider)

# Use authentication dependency
@app.get("/users/me")
async def get_user_profile(user = Depends(authenticator.get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "realm_roles": user.realm_roles,
        "client_roles": user.client_roles,
    }
```

### Protected Endpoints with Role Requirements

```python
from fastapi import FastAPI, Depends
from miraveja_auth.infrastructure import FastAPIAuthenticator

authenticator = FastAPIAuthenticator(provider)

@app.get("/admin/users")
async def list_all_users(user = Depends(authenticator.require_realm_role("admin"))):
    # Only users with 'admin' realm role can access
    return {"users": [...]}

@app.post("/api/documents")
async def create_document(user = Depends(authenticator.require_client_role("api-client", "write:documents"))):
    # Only users with 'write:documents' role for 'api-client' can create
    return {"document_id": 123}
```

### Optional Authentication

```python
from typing import Optional
from miraveja_auth.infrastructure import FastAPIAuthenticator
from miraveja_auth.domain import User

authenticator = FastAPIAuthenticator(provider)

@app.get("/public/content")
async def get_content(user: Optional[User] = Depends(authenticator.get_current_user_optional)):
    if user:
        # Return personalized content for authenticated users
        return {"content": f"Welcome back, {user.username}!"}
    else:
        # Return public content for anonymous users
        return {"content": "Welcome, guest!"}
```

### Complete FastAPI Example

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
    AuthenticationError,
    AuthorizationError,
)
from miraveja_auth.infrastructure import FastAPIAuthenticator

# Initialize FastAPI app
app = FastAPI(title="My Secured API")

# Configure OAuth2/OIDC authentication
config = OAuth2Configuration(
    issuer="https://keycloak.example.com/realms/myrealm",
    client_id="my-api",
    client_secret="secret",
)
discovery = OIDCDiscoveryService(config)
provider = OAuth2Provider(config, discovery)
authenticator = FastAPIAuthenticator(provider)

# Public endpoint (no authentication)
@app.get("/")
async def root():
    return {"message": "Welcome to My Secured API"}

# Protected endpoint (authentication required)
@app.get("/profile")
async def get_profile(user = Depends(authenticator.get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
    }

# Admin endpoint (requires 'admin' realm role)
@app.get("/admin/dashboard")
async def admin_dashboard(user = Depends(authenticator.require_realm_role("admin"))):
    return {"message": f"Welcome to admin dashboard, {user.username}"}

# API endpoint (requires client-specific role)
@app.post("/api/documents")
async def create_document(
    document: dict,
    user = Depends(authenticator.require_client_role("my-api", "write:documents"))
):
    return {
        "id": 123,
        "created_by": user.username,
        "data": document,
    }

# Mixed endpoint (optional authentication)
@app.get("/content")
async def get_content(user = Depends(authenticator.get_current_user_optional)):
    if user:
        return {"message": f"Hello, {user.username}!", "premium": True}
    return {"message": "Hello, guest!", "premium": False}

# Global exception handlers
@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request, exc):
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=str(exc),
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.exception_handler(AuthorizationError)
async def authorization_error_handler(request, exc):
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=str(exc),
    )
```

### WebSocket Support

FastAPI authenticators support both HTTP and WebSocket connections through separate implementations:

```python
from fastapi import FastAPI, Depends, WebSocket
from miraveja_auth import OAuth2Configuration, OAuth2Provider, OIDCDiscoveryService
from miraveja_auth.infrastructure import FastAPIAuthenticator
from miraveja_auth.domain import User

app = FastAPI()

# Setup
config = OAuth2Configuration.from_env()
discovery = OIDCDiscoveryService(config)
provider = OAuth2Provider(config, discovery)
authenticator = FastAPIAuthenticator(provider)

# HTTP endpoint - uses Authorization header
@app.get("/api/data")
async def get_data(user: User = Depends(authenticator.get_current_user)):
    return {"data": "...", "user": user.username}

# WebSocket endpoint - uses query parameter (?token=...)
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    user: User = Depends(authenticator.ws.get_current_user)
):
    await websocket.accept()
    await websocket.send_json({
        "message": f"Connected as {user.username}",
        "roles": user.realm_roles
    })

    while True:
        data = await websocket.receive_text()
        await websocket.send_json({"echo": data})
```

### Separate Authenticators (Advanced)

For more control, use HTTP and WebSocket authenticators separately:

```python
from miraveja_auth.infrastructure import HTTPAuthenticator, WebSocketAuthenticator

# Create separate authenticators
http_auth = HTTPAuthenticator(provider)
ws_auth = WebSocketAuthenticator(provider)

# HTTP endpoints
@app.get("/api/profile")
async def profile(user: User = Depends(http_auth.get_current_user)):
    return {"id": user.id, "username": user.username}

@app.get("/api/admin")
async def admin(user: User = Depends(http_auth.require_realm_role("admin"))):
    return {"message": "Admin area"}

# WebSocket endpoints
@app.websocket("/ws/notifications")
async def notifications(
    websocket: WebSocket,
    user: User = Depends(ws_auth.get_current_user)
):
    await websocket.accept()
    # ... handle WebSocket communication

# Optional WebSocket authentication
@app.websocket("/ws/public")
async def public_ws(
    websocket: WebSocket,
    user: User = Depends(ws_auth.get_current_user_optional)
):
    await websocket.accept()
    if user:
        await websocket.send_json({"user": user.username})
    else:
        await websocket.send_json({"user": "anonymous"})
```

## 🔧 Configuration

### OAuth2Configuration Model

```python
from miraveja_auth import OAuth2Configuration

config = OAuth2Configuration(
    issuer="https://keycloak.example.com/realms/myrealm",  # OIDC issuer URL
    client_id="my-client",                                  # OAuth2 client ID
    client_secret="your-secret",                            # OAuth2 client secret (optional)
    verify_ssl=True,                                         # Verify SSL certificates (default: True)
    public_key=None,                                         # Static public key (optional, for offline validation)
    token_verification_algorithm="RS256",                    # JWT algorithm (default: RS256)
    token_minimum_ttl=60,                                    # Minimum token TTL in seconds (default: 60)
)
```

### Environment Variables

Configure your OAuth2/OIDC provider using environment variables:

```bash
# Required
OAUTH2_ISSUER=https://keycloak.example.com/realms/myrealm  # OIDC issuer URL
OAUTH2_CLIENT_ID=my-client                                   # OAuth2 client ID

# Optional
OAUTH2_CLIENT_SECRET=your-secret                             # Client secret (for confidential clients)
OAUTH2_VERIFY_SSL=true                                       # Verify SSL certificates (default: true)
OAUTH2_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----...             # Static public key for offline validation
OAUTH2_TOKEN_ALGORITHM=RS256                                 # JWT verification algorithm (default: RS256)
OAUTH2_TOKEN_MIN_TTL=60                                      # Minimum token TTL in seconds (default: 60)
```

Then load configuration:

```python
from miraveja_auth import OAuth2Configuration

config = OAuth2Configuration.from_env()
```

### Supported OAuth2/OIDC Providers

miraveja-authentication works with any OAuth2/OpenID Connect compliant provider:

#### Keycloak

```python
config = OAuth2Configuration(
    issuer="https://keycloak.example.com/realms/myrealm",
    client_id="my-client",
    client_secret="your-secret",
)
```

#### Auth0

```python
config = OAuth2Configuration(
    issuer="https://your-tenant.auth0.com/",
    client_id="your-client-id",
    client_secret="your-client-secret",
)
```

#### AWS Cognito

```python
config = OAuth2Configuration(
    issuer="https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
    client_id="your-app-client-id",
    client_secret="your-app-client-secret",
)
```

#### Azure AD (Microsoft Entra)

```python
config = OAuth2Configuration(
    issuer="https://login.microsoftonline.com/{tenant-id}/v2.0",
    client_id="your-application-id",
    client_secret="your-client-secret",
)
```

#### Google

```python
config = OAuth2Configuration(
    issuer="https://accounts.google.com",
    client_id="your-client-id.apps.googleusercontent.com",
    client_secret="your-client-secret",
)
```

#### Okta

```python
config = OAuth2Configuration(
    issuer="https://your-domain.okta.com/oauth2/default",
    client_id="your-client-id",
    client_secret="your-client-secret",
)
```

## 📚 API Reference

### OAuth2Configuration

Pydantic model for OAuth2/OIDC configuration with validation.

**Fields:**

- `issuer: str` - OIDC issuer URL (required)
- `client_id: str` - OAuth2 client ID (required)
- `client_secret: Optional[str]` - Client secret for confidential clients
- `verify_ssl: bool` - Verify SSL certificates (default: True)
- `public_key: Optional[str]` - Static public key for offline validation
- `token_verification_algorithm: str` - JWT algorithm (default: RS256)
- `token_minimum_ttl: int` - Minimum token TTL in seconds (default: 60)

**Class Methods:**

- `from_env() -> OAuth2Configuration`
  - Creates configuration from environment variables
  - Returns: OAuth2Configuration instance
  - Validates required fields (OAUTH2_ISSUER, OAUTH2_CLIENT_ID)

**Validators:**

- `validate_issuer()` - Ensures issuer is a valid HTTPS URL

### OAuth2Provider

Token validation use case in the application layer. Orchestrates the validation flow.

**Constructor:**

```python
OAuth2Provider(
    config: OAuth2Configuration,
    discovery_service: IOIDCDiscoveryService,
    role_mapper: Optional[IRoleMapper] = None
)
```

- `config`: OAuth2Configuration instance
- `discovery_service`: OIDC discovery service (e.g., OIDCDiscoveryService)
- `role_mapper`: Custom role mapper (default: KeycloakRoleMapper)

**Methods:**

- `async validate_token(token: str) -> User`
  - Validates JWT token and returns User instance
  - Checks expiration and minimum TTL
  - Verifies signature (offline with static key or online with JWKS)
  - Parses claims into User model with roles
  - Raises: `TokenExpiredError`, `TokenInvalidError`, `AuthenticationError`

### OIDCDiscoveryService

HTTP-based OIDC discovery and JWKS service in the infrastructure layer.

**Constructor:**

```python
OIDCDiscoveryService(config: OAuth2Configuration)
```

**Methods:**

- `async get_signing_key(token: str) -> Any`
  - Gets signing key for JWT validation from JWKS
  - Caches keys for 1 hour
  - Raises: `AuthenticationError`

- `async discover_configuration() -> Dict[str, Any]`
  - Fetches OIDC discovery configuration from `.well-known/openid-configuration`
  - Returns: OIDC configuration dictionary
  - Raises: `AuthenticationError`

### Domain Models

#### User

User representation with authentication claims and roles.

**Fields:**

- `id: str` - User ID (from 'sub' claim)
- `username: str` - Username (from 'preferred_username' claim)
- `email: Optional[str]` - User email
- `realm_roles: List[str]` - Realm-level roles
- `client_roles: Dict[str, List[str]]` - Client-specific roles

**Class Methods:**

- `from_claims(claims: Claims) -> User` - Create User from JWT claims

**Instance Methods:**

- `has_realm_role(role: str) -> bool` - Check if user has a specific realm role
- `require_realm_role(role: str) -> None` - Require user to have a realm role (raises AuthorizationError if missing)
- `has_client_role(client: str, role: str) -> bool` - Check if user has a client-specific role
- `require_client_role(client: str, role: str) -> None` - Require user to have a client role (raises AuthorizationError if missing)

#### Claims

JWT token claims representation.

**Fields:**

- `iss: str` - Issuer
- `sub: str` - Subject (user ID)
- `aud: str | List[str]` - Audience
- `exp: int` - Expiration timestamp
- `iat: int` - Issued at timestamp
- Additional OIDC standard claims (email, preferred_username, etc.)
- Keycloak extensions (realm_access, resource_access)

#### Token

OAuth2 token representation.

**Fields:**

- `access_token: str` - JWT access token
- `refresh_token: Optional[str]` - Refresh token
- `expires_in: int` - Token lifetime in seconds

#### Role

Role value object.

**Fields:**

- `id: str` - Role ID
- `name: str` - Role name
- `description: Optional[str]` - Role description
- `composite: bool` - Whether role is composite
- `client_role: bool` - Whether role is client-specific
- `container_id: Optional[str]` - Container (realm or client) ID

### FastAPI Integration

#### FastAPIAuthenticator

Unified authenticator providing both HTTP and WebSocket authentication.

**Constructor:**

```python
FastAPIAuthenticator(
    provider: IOAuth2Provider,
    role_mapper: Optional[IRoleMapper] = None
)
```

**Properties:**

- `http: HTTPAuthenticator` - HTTP-specific authenticator
- `ws: WebSocketAuthenticator` - WebSocket-specific authenticator

**Methods (HTTP delegation):**

- `get_current_user(token: str) -> User` - Validate token and return user (raises on failure)
- `get_current_user_optional(token: Optional[str]) -> Optional[User]` - Validate token if provided
- `require_realm_role(*roles: str)` - Dependency requiring any of the specified realm roles
- `require_client_role(client_id: str, *roles: str)` - Dependency requiring client-specific roles

**Usage:**

```python
from miraveja_auth.infrastructure.fastapi_integration import FastAPIAuthenticator

authenticator = FastAPIAuthenticator(provider)

# Use .http for HTTP endpoints
@app.get("/users/me")
async def read_current_user(user: User = Depends(authenticator.http.get_current_user)):
    return user

# Use .ws for WebSocket endpoints
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    user = await authenticator.ws.get_current_user(websocket)
    await websocket.accept()
```

#### HTTPAuthenticator

HTTP-specific authenticator extracting JWT from `Authorization: Bearer` header.

**Constructor:**

```python
HTTPAuthenticator(
    provider: IOAuth2Provider,
    role_mapper: Optional[IRoleMapper] = None
)
```

**Methods:**

- `get_current_user(token: str = Depends(oauth2_scheme)) -> User` - FastAPI dependency for HTTP endpoints
- `get_current_user_optional(token: Optional[str] = Depends(optional_oauth2_scheme)) -> Optional[User]`
- `require_realm_role(*roles: str)` - Dependency requiring realm roles
- `require_client_role(client_id: str, *roles: str)` - Dependency requiring client roles

#### WebSocketAuthenticator

WebSocket-specific authenticator extracting JWT from query parameter `?token=...`.

**Constructor:**

```python
WebSocketAuthenticator(
    provider: IOAuth2Provider,
    role_mapper: Optional[IRoleMapper] = None
)
```

**Methods:**

- `get_current_user(websocket: WebSocket) -> User` - Extract and validate token from WebSocket query parameters
- `get_current_user_optional(websocket: WebSocket) -> Optional[User]` - Optional WebSocket authentication
- `require_realm_role(websocket: WebSocket, *roles: str) -> User` - Validate token and require realm roles
- `require_client_role(websocket: WebSocket, client_id: str, *roles: str) -> User` - Validate token and require client roles

**Note:** WebSocket authentication extracts the token from the query parameter (e.g., `ws://localhost:8000/ws?token=eyJ...`) since WebSockets don't support custom headers in browsers.

#### KeycloakRoleMapper

Role mapper for Keycloak-specific token claims.

**Constructor:**

```python
KeycloakRoleMapper()
```

**Methods:**

- `extract_realm_roles(claims: Claims) -> List[str]` - Extract roles from `realm_access.roles`
- `extract_client_roles(claims: Claims) -> Dict[str, List[str]]` - Extract client roles from `resource_access`

**Usage:**

```python
from miraveja_auth.infrastructure import KeycloakRoleMapper

mapper = KeycloakRoleMapper()
provider = OAuth2Provider(config, discovery_service, role_mapper=mapper)
```

#### MockOAuth2Provider

Testing utility for simulating OAuth2 authentication without a real provider.

**Constructor:**

```python
MockOAuth2Provider()
```

**Methods:**

- `add_user(user_id: str, username: str, email: Optional[str] = None, realm_roles: List[str] = [], client_roles: Dict[str, List[str]] = {})` - Add test user
- `set_token_for_user(user_id: str) -> str` - Generate mock token for user
- `simulate_failure(error_type: Literal["expired", "invalid", "missing"])` - Simulate authentication failures
- `validate_token(token: str) -> User` - Validate mock token
- `get_user_by_id(user_id: str) -> User` - Get user directly by ID

**Usage:**

```python
from miraveja_auth.infrastructure.testing import MockOAuth2Provider

mock_provider = MockOAuth2Provider()
mock_provider.add_user("123", "testuser", realm_roles=["admin"])
token = mock_provider.set_token_for_user("123")

user = await mock_provider.validate_token(token)
```

### Exceptions

- `AuthenticationError` - Base exception for authentication failures
- `TokenExpiredError` - Token has expired (includes expiration time and TTL)
- `TokenInvalidError` - Token signature or structure is invalid
- `AuthorizationError` - User lacks required permissions
- `ConfigurationError` - Invalid configuration

## 🔥 Advanced Usage

### Custom Role Mapper

Create custom role mappers for different OAuth2/OIDC providers:

```python
from miraveja_auth import IRoleMapper, OAuth2Provider, Claims
from typing import List, Dict

class Auth0RoleMapper(IRoleMapper):
    """Role mapper for Auth0 custom claims."""

    def extract_realm_roles(self, claims: Claims) -> List[str]:
        # Auth0 stores roles in custom namespace
        return claims.get("https://myapp.com/roles", [])

    def extract_client_roles(self, claims: Claims) -> Dict[str, List[str]]:
        # Auth0 typically doesn't use client-specific roles
        return {}

# Use custom mapper
config = OAuth2Configuration.from_env()
mapper = Auth0RoleMapper()
provider = OAuth2Provider(config, role_mapper=mapper)
```

### Offline Token Validation

For offline validation without JWKS fetching:

```python
from miraveja_auth import OAuth2Configuration, OAuth2Provider

config = OAuth2Configuration(
    issuer="https://keycloak.example.com/realms/myrealm",
    client_id="my-client",
    public_key="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----""",
)

provider = OAuth2Provider(config)
# Token validation uses static public key instead of JWKS
user = await provider.validate_token(token)
```

### Multiple OAuth2 Providers

Support multiple authentication providers:

```python
from miraveja_auth import OAuth2Configuration, OAuth2Provider

# Keycloak provider
keycloak_config = OAuth2Configuration(
    issuer="https://keycloak.example.com/realms/internal",
    client_id="internal-api",
)
keycloak_provider = OAuth2Provider(keycloak_config)

# Auth0 provider
auth0_config = OAuth2Configuration(
    issuer="https://your-tenant.auth0.com/",
    client_id="external-api",
)
auth0_provider = OAuth2Provider(auth0_config)

# Validate against appropriate provider
async def authenticate(token: str, provider_type: str):
    if provider_type == "keycloak":
        return await keycloak_provider.validate_token(token)
    elif provider_type == "auth0":
        return await auth0_provider.validate_token(token)
```

### Custom Token TTL Validation

Ensure tokens have sufficient remaining lifetime:

```python
config = OAuth2Configuration(
    issuer="https://keycloak.example.com/realms/myrealm",
    client_id="my-client",
    token_minimum_ttl=300,  # Require at least 5 minutes remaining
)
provider = OAuth2Provider(config)

# Raises TokenExpiredError if token expires in less than 5 minutes
user = await provider.validate_token(token)
```

## 🧪 Testing

### Using MockOAuth2Provider

The `MockOAuth2Provider` allows you to create test environments with simulated authentication:

```python
from miraveja_auth.infrastructure.testing import MockOAuth2Provider
import pytest

@pytest.fixture
def mock_provider():
    return MockOAuth2Provider()

@pytest.mark.asyncio
async def test_user_authentication(mock_provider):
    # Add test user with roles
    mock_provider.add_user(
        user_id="123",
        username="testuser",
        email="test@example.com",
        realm_roles=["user", "admin"],
        client_roles={"my-client": ["read", "write"]},
    )

    # Get token for user
    token = mock_provider.set_token_for_user("123")

    # Validate token
    user = await mock_provider.validate_token(token)

    assert user.id == "123"
    assert user.username == "testuser"
    assert "admin" in user.realm_roles
    assert "read" in user.client_roles["my-client"]
```

### Simulating Authentication Failures

```python
@pytest.mark.asyncio
async def test_expired_token(mock_provider):
    mock_provider.add_user("123", "testuser")

    # Simulate token expiration
    mock_provider.simulate_failure("expired")

    with pytest.raises(TokenExpiredError):
        await mock_provider.validate_token("any-token")
```

### Testing FastAPI Dependencies

```python
from fastapi.testclient import TestClient
from miraveja_auth.infrastructure.fastapi_integration import FastAPIAuthenticator
from miraveja_auth.infrastructure.testing import MockOAuth2Provider

def test_protected_endpoint():
    # Setup mock provider
    mock_provider = MockOAuth2Provider()
    mock_provider.add_user(
        "123",
        "testuser",
        realm_roles=["admin"]
    )
    token = mock_provider.set_token_for_user("123")

    # Create authenticator with mock provider
    authenticator = FastAPIAuthenticator(mock_provider)

    # Test endpoint
    client = TestClient(app)
    response = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=src/miraveja_auth --cov-report=html

# Run specific test file
poetry run pytest tests/unit/miraveja_auth/domain/test_models.py

# Run with verbose output
poetry run pytest -v

# Run integration tests only
poetry run pytest tests/integration

# Run unit tests only
poetry run pytest tests/unit
```

## 📂 Examples

Complete working examples are available in the `examples/` directory:

- **`basic_validation.py`** - Basic token validation and role checking
- **`fastapi_app.py`** - Complete FastAPI application with authentication

Run examples:

```bash
# Basic validation
poetry run python examples/basic_validation.py

# FastAPI app (requires uvicorn)
poetry run uvicorn examples.fastapi_app:app --reload
```

## 💡 Best Practices

1. **Use environment variables**: Store OAuth2 configuration in environment variables, not in code
2. **Enable SSL verification**: Always use `verify_ssl=True` in production
3. **Validate token TTL**: Set appropriate `token_minimum_ttl` to ensure tokens have sufficient lifetime
4. **Use role-based authorization**: Leverage realm and client roles for fine-grained access control
5. **Handle exceptions properly**: Catch `AuthenticationError` and `AuthorizationError` in your application
6. **Test with mocks**: Use `MockOAuth2Provider` for unit and integration tests
7. **Cache provider instances**: Reuse `OAuth2Provider` instances to benefit from key caching

## 🚧 Development Status

**Active Development** - Core features implemented and tested

🚀 **Planned Features:**

- OAuth2/OIDC protocol implementation
- JWT token validation with JWKS
- Automatic OIDC discovery
- Role-based authorization (Keycloak-style)
- FastAPI integration with dependency injection
- Testing utilities (MockOAuth2Provider)
- Exception handling and error reporting
- Environment-based configuration
- Additional role mappers (Auth0, Cognito, Azure AD)
- Token refresh support
- WebSocket authentication
- GraphQL integration
- Performance optimizations (connection pooling, key caching improvements)

See the [implementation plan](.github/prompts/plan-miravejaAuthentication.prompt.md) for detailed design notes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/JomarJunior/miraveja-authentication.git
cd miraveja-authentication

# Install dependencies
poetry install

# Install pre-commit hooks
poetry run pre-commit install

# Run tests
poetry run pytest --cov=src/miraveja_auth
```

### Code Quality

```bash
# Format code
poetry run black src tests

# Sort imports
poetry run isort src tests

# Run linter
poetry run pylint src/miraveja_auth

# Run type checker
poetry run mypy src/miraveja_auth

# Run pre-commit hooks
poetry run pre-commit run --all-files
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built as part of the Miraveja ecosystem
- Follows OAuth2/OpenID Connect standards
- Inspired by Keycloak's role-based authorization model
- Follows DDD/Hexagonal Architecture principles

## 📞 Contact

- **Author**: Jomar Júnior de Souza Pereira
- **Email**: <jomarjunior@poli.ufrj.br>
- **Repository**: <https://github.com/JomarJunior/miraveja-authentication>

## 🔗 Related Projects

- [miraveja-di](https://github.com/JomarJunior/miraveja-di) - Dependency Injection container
- [miraveja-log](https://github.com/JomarJunior/miraveja-log) - Logging library
- [miraveja](https://github.com/JomarJunior/miraveja) - Main Miraveja project

---

Made with ❤️ for the Miraveja ecosystem
