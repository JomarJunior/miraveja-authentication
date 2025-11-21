"""Infrastructure layer - External integrations."""

from .services import OIDCDiscoveryService
from .testing import MockOAuth2Provider

__all__ = [
    "OIDCDiscoveryService",
    "MockOAuth2Provider",
]

# FastAPI integration (optional)
try:
    from .fastapi_integration import (
        FastAPIAuthenticator,
        HTTPAuthenticator,
        WebSocketAuthenticator,
    )

    __all__.extend(["HTTPAuthenticator", "WebSocketAuthenticator", "FastAPIAuthenticator"])
except ImportError:
    pass  # FastAPI not installed
