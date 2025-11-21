"""miraveja-authentication - OAuth2/OIDC authentication library.

Public API exports.
"""

__version__ = "0.1.0"

# Application exports
from .application import OAuth2Configuration, OAuth2Provider

# Domain exports
from .domain import (
    AuthenticationException,
    AuthorizationException,
    BaseClaims,
    ConfigurationException,
    IAuthenticator,
    IOAuth2Provider,
    IOIDCDiscoveryService,
    Role,
    Token,
    TokenExpiredException,
    TokenInvalidException,
    User,
)

# Infrastructure exports
from .infrastructure import (
    MockOAuth2Provider,
    OIDCDiscoveryService,
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
    "IOIDCDiscoveryService",
    "IAuthenticator",
    "AuthenticationException",
    "TokenExpiredException",
    "TokenInvalidException",
    "AuthorizationException",
    "ConfigurationException",
    # Application
    "OAuth2Configuration",
    "OAuth2Provider",
    # Infrastructure
    "OIDCDiscoveryService",
    "MockOAuth2Provider",
]

# FastAPI integration (conditional)
try:
    from .infrastructure import (
        FastAPIAuthenticator,
        HTTPAuthenticator,
        WebSocketAuthenticator,
    )

    __all__.extend(["HTTPAuthenticator", "WebSocketAuthenticator", "FastAPIAuthenticator"])
except ImportError:
    pass  # FastAPI not installed
