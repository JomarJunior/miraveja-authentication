"""
Domain Layer

Contains core business logic, domain models, interfaces, and exceptions.
This layer has no dependencies on other layers or external frameworks.
"""

from miraveja_auth.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    TokenExpiredError,
    TokenInvalidError,
)
from miraveja_auth.domain.interfaces import (
    IAuthenticator,
    IOAuth2Provider,
    IOIDCDiscoveryService,
    IRoleMapper,
)
from miraveja_auth.domain.models import Claims, Role, Token, User

__all__ = [
    # Models
    "User",
    "Claims",
    "Token",
    "Role",
    # Interfaces
    "IOAuth2Provider",
    "IRoleMapper",
    "IOIDCDiscoveryService",
    "IAuthenticator",
    # Exceptions
    "AuthenticationError",
    "TokenExpiredError",
    "TokenInvalidError",
    "AuthorizationError",
    "ConfigurationError",
]
