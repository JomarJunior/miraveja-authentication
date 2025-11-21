"""Using separate HTTP and WebSocket authenticators."""

from fastapi import Depends, FastAPI, WebSocket

from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
)
from miraveja_auth.domain import User
from miraveja_auth.infrastructure import HTTPAuthenticator, WebSocketAuthenticator
from miraveja_auth.infrastructure.providers.keycloak import KeycloakClaimsParser

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
async def ws_notifications(websocket: WebSocket, user: User = Depends(ws_auth.get_current_user)):
    await websocket.accept()
    await websocket.send_json({"type": "connected", "user": user.username, "roles": user.realm_roles})

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
