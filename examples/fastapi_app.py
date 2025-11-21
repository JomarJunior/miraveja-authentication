"""FastAPI application example."""

from fastapi import Depends, FastAPI, WebSocket

from miraveja_auth import (
    OAuth2Configuration,
    OAuth2Provider,
    OIDCDiscoveryService,
)
from miraveja_auth.domain import User
from miraveja_auth.infrastructure import FastAPIAuthenticator
from miraveja_auth.infrastructure.providers.keycloak import KeycloakClaimsParser

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
async def profile(user: User = Depends(authenticator.http.get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "roles": user.realm_roles,
    }


@app.get("/admin")
async def admin(user: User = Depends(authenticator.http.require_realm_role("admin"))):
    return {"message": f"Hello admin {user.username}"}


# WebSocket endpoint - use .ws
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, user: User = Depends(authenticator.ws.get_current_user)):
    await websocket.accept()
    await websocket.send_json({"message": f"Connected as {user.username}"})
    # ... handle WebSocket communication
    # ... handle WebSocket communication
