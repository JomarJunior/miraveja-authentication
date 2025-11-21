"""Domain layer - Core business logic."""

from .exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConfigurationException,
    TokenExpiredException,
    TokenInvalidException,
)
from .interfaces import (
    IAuthenticator,
    IClaimsParser,
    IOAuth2Provider,
    IOIDCDiscoveryService,
)
from .models import BaseClaims, Role, Token, User

__all__ = [
    "User",
    "BaseClaims",
    "Token",
    "Role",
    "IOAuth2Provider",
    "IClaimsParser",
    "IOIDCDiscoveryService",
    "IAuthenticator",
    "AuthenticationException",
    "TokenExpiredException",
    "TokenInvalidException",
    "AuthorizationException",
    "ConfigurationException",
]
