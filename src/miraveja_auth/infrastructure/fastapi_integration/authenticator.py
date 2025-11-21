from miraveja_auth.domain import IOAuth2Provider
from miraveja_auth.infrastructure.fastapi_integration.http_authenticator import HTTPAuthenticator
from miraveja_auth.infrastructure.fastapi_integration.websocket_authenticator import WebSocketAuthenticator


class FastAPIAuthenticator:
    """Unified authenticator with both HTTP and WebSocket support.

    Convenience class that provides access to both HTTP and WebSocket
    authenticators through a single instance.

    Examples:
        Basic usage with HTTP endpoints::

            from fastapi import FastAPI, Depends
            from miraveja_auth.infrastructure import FastAPIAuthenticator

            authenticator = FastAPIAuthenticator(provider)

            @app.get("/profile")
            async def profile(user = Depends(authenticator.http.get_current_user)):
                return {"id": user.id}

        WebSocket usage::

            @app.websocket("/ws")
            async def websocket_endpoint(
                websocket: WebSocket,
                user = Depends(authenticator.ws.get_current_user)
            ):
                await websocket.accept()
                await websocket.send_json({"user": user.username})
    """

    def __init__(self, provider: IOAuth2Provider):
        """Initialize unified FastAPI authenticator.

        Args:
            provider: OAuth2 provider for token validation.
        """
        self._http = HTTPAuthenticator(provider)
        self._ws = WebSocketAuthenticator(provider)

    @property
    def http(self) -> HTTPAuthenticator:
        """Access the HTTP authenticator."""
        return self._http

    @property
    def ws(self) -> WebSocketAuthenticator:
        """Access the WebSocket authenticator."""
        return self._ws
