"""
Miraveja Authentication Library

A modern OAuth2/OIDC authentication library with FastAPI integration.
Follows DDD/Hexagonal Architecture principles.
"""

from miraveja_auth.application.configuration import OAuth2Configuration
from miraveja_auth.application.oauth2_provider import OAuth2Provider
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

__version__ = "0.1.0"

__all__ = [
    # Domain Models
    "User",
    "Claims",
    "Token",
    "Role",
    # Domain Interfaces
    "IOAuth2Provider",
    "IRoleMapper",
    "IOIDCDiscoveryService",
    "IAuthenticator",
    # Domain Exceptions
    "AuthenticationError",
    "TokenExpiredError",
    "TokenInvalidError",
    "AuthorizationError",
    "ConfigurationError",
    # Application Layer
    "OAuth2Configuration",
    "OAuth2Provider",
]
