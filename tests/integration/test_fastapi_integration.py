"""Integration tests for FastAPI authentication and authorization.

Note: These are simplified integration tests focusing on key scenarios.
Full endpoint testing is covered in unit tests.
"""

import time
from typing import Optional
from unittest.mock import AsyncMock

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocket

from miraveja_auth.domain.exceptions import (
    AuthenticationException,
    AuthorizationException,
    TokenExpiredException,
    TokenInvalidException,
)
from miraveja_auth.domain.interfaces import IOAuth2Provider
from miraveja_auth.domain.models import User
from miraveja_auth.infrastructure.fastapi_integration.authenticator import (
    FastAPIAuthenticator,
)
from miraveja_auth.infrastructure.fastapi_integration.http_authenticator import (
    HTTPAuthenticator,
)
from miraveja_auth.infrastructure.fastapi_integration.websocket_authenticator import (
    WebSocketAuthenticator,
)


class MockOAuth2ProviderForFastAPI(IOAuth2Provider):
    """Mock OAuth2 provider for FastAPI integration tests."""

    def __init__(self):
        self._users = {}
        self._tokens = {}

    def add_user(self, user: User, token: str):
        """Add a user and token mapping."""
        self._users[user.id] = user
        self._tokens[token] = user.id

    async def validate_token(self, token: str) -> User:
        """Validate token and return user."""
        user_id = self._tokens.get(token)
        if not user_id:
            raise TokenInvalidException()

        user = self._users.get(user_id)
        if not user:
            raise TokenInvalidException()

        return user


class TestHTTPAuthenticatorIntegration:
    """Integration tests for HTTPAuthenticator with FastAPI.

    These tests verify that authenticators integrate correctly with FastAPI's
    dependency injection system.
    """

    @pytest.mark.asyncio
    async def test_validate_token_method(self):
        """Test that _validate_token works correctly with mock provider."""
        provider = MockOAuth2ProviderForFastAPI()
        user = User(
            id="user-123",
            username="testuser",
            realm_roles=["user"],
            client_roles={},
        )
        provider.add_user(user, "token-123")

        authenticator = HTTPAuthenticator(provider)

        # Test successful validation
        result = await authenticator._validate_token("token-123")
        assert result.id == "user-123"
        assert result.username == "testuser"

        # Test invalid token raises HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await authenticator._validate_token("invalid-token")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_require_realm_role_dependency(self):
        """Test that require_realm_role dependency works correctly."""
        provider = MockOAuth2ProviderForFastAPI()
        user_with_role = User(
            id="admin-user",
            username="admin",
            realm_roles=["admin"],
            client_roles={},
        )
        user_without_role = User(
            id="regular-user",
            username="regular",
            realm_roles=["user"],
            client_roles={},
        )

        authenticator = HTTPAuthenticator(provider)
        role_dependency = authenticator.require_realm_role("admin")

        # User with role should pass
        result = await role_dependency(user_with_role)
        assert result.id == "admin-user"

        # User without role should raise 403
        with pytest.raises(HTTPException) as exc_info:
            await role_dependency(user_without_role)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_client_role_dependency(self):
        """Test that require_client_role dependency works correctly."""
        provider = MockOAuth2ProviderForFastAPI()
        user_with_role = User(
            id="app-admin",
            username="appadmin",
            realm_roles=[],
            client_roles={"test-client": ["app-admin"]},
        )
        user_without_role = User(
            id="viewer",
            username="viewer",
            realm_roles=[],
            client_roles={"test-client": ["viewer"]},
        )

        authenticator = HTTPAuthenticator(provider)
        role_dependency = authenticator.require_client_role("test-client", "app-admin")

        # User with role should pass
        result = await role_dependency(user_with_role)
        assert result.id == "app-admin"

        # User without role should raise 403
        with pytest.raises(HTTPException) as exc_info:
            await role_dependency(user_without_role)
        assert exc_info.value.status_code == 403


class TestWebSocketAuthenticatorIntegration:
    """Integration tests for WebSocketAuthenticator with FastAPI.

    These tests verify WebSocket authenticator integration works correctly.
    """

    @pytest.mark.asyncio
    async def test_validate_token_method(self):
        """Test that _validate_token works correctly for WebSocket authenticator."""
        provider = MockOAuth2ProviderForFastAPI()
        user = User(
            id="ws-user-123",
            username="wsuser",
            realm_roles=["user"],
            client_roles={},
        )
        provider.add_user(user, "ws-token-123")

        authenticator = WebSocketAuthenticator(provider)

        # Test successful validation
        result = await authenticator._validate_token("ws-token-123")
        assert result.id == "ws-user-123"
        assert result.username == "wsuser"

        # Test invalid token raises HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await authenticator._validate_token("invalid-token")
        assert exc_info.value.status_code == 401


class TestFastAPIAuthenticatorUnified:
    """Integration tests for unified FastAPIAuthenticator."""

    def test_unified_authenticator_properties(self):
        """Test that unified authenticator provides http and ws properties."""
        provider = MockOAuth2ProviderForFastAPI()
        authenticator = FastAPIAuthenticator(provider)

        # Verify properties exist and are correct types
        assert isinstance(authenticator.http, HTTPAuthenticator)
        assert isinstance(authenticator.ws, WebSocketAuthenticator)
        assert authenticator.http._provider is provider
        assert authenticator.ws._provider is provider

    @pytest.mark.asyncio
    async def test_both_authenticators_share_provider(self):
        """Test that both HTTP and WS authenticators use the same provider."""
        provider = MockOAuth2ProviderForFastAPI()
        user = User(
            id="shared-user",
            username="shareduser",
            realm_roles=["user"],
            client_roles={},
        )
        provider.add_user(user, "shared-token")

        authenticator = FastAPIAuthenticator(provider)

        # Both should validate the same token successfully
        http_result = await authenticator.http._validate_token("shared-token")
        ws_result = await authenticator.ws._validate_token("shared-token")

        assert http_result.id == ws_result.id == "shared-user"
        assert http_result.username == ws_result.username == "shareduser"
