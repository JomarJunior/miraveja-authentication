"""Unit tests for FastAPI authenticator integration."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from miraveja_auth.domain import AuthenticationException, AuthorizationException, User
from miraveja_auth.infrastructure.fastapi_integration import (
    FastAPIAuthenticator,
    HTTPAuthenticator,
    WebSocketAuthenticator,
)
from miraveja_auth.infrastructure.fastapi_integration.base import BaseFastAPIAuthenticator


class TestFastAPIAuthenticatorInitialization:
    """Test FastAPIAuthenticator initialization."""

    def test_init_creates_http_and_ws_authenticators(self):
        """Test that __init__ creates HTTP and WebSocket authenticators."""
        mock_provider = MagicMock()
        authenticator = FastAPIAuthenticator(mock_provider)

        assert isinstance(authenticator._http, HTTPAuthenticator)
        assert isinstance(authenticator._ws, WebSocketAuthenticator)
        assert authenticator._http._provider is mock_provider
        assert authenticator._ws._provider is mock_provider

    def test_http_property_returns_http_authenticator(self):
        """Test that http property returns HTTPAuthenticator."""
        mock_provider = MagicMock()
        authenticator = FastAPIAuthenticator(mock_provider)

        result = authenticator.http

        assert result is authenticator._http
        assert isinstance(result, HTTPAuthenticator)

    def test_ws_property_returns_websocket_authenticator(self):
        """Test that ws property returns WebSocketAuthenticator."""
        mock_provider = MagicMock()
        authenticator = FastAPIAuthenticator(mock_provider)

        result = authenticator.ws

        assert result is authenticator._ws
        assert isinstance(result, WebSocketAuthenticator)


class TestBaseFastAPIAuthenticatorInitialization:
    """Test BaseFastAPIAuthenticator initialization via concrete class."""

    def test_init_stores_provider(self):
        """Test that __init__ stores the OAuth2 provider."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        assert authenticator._provider is mock_provider


class TestBaseFastAPIAuthenticatorValidateToken:
    """Test _validate_token method via HTTPAuthenticator."""

    @pytest.mark.asyncio
    async def test_validate_token_success(self):
        """Test successful token validation."""
        mock_provider = AsyncMock()
        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={},
        )
        mock_provider.validate_token.return_value = mock_user

        authenticator = HTTPAuthenticator(mock_provider)

        result = await authenticator._validate_token("valid-token")

        assert result is mock_user
        mock_provider.validate_token.assert_called_once_with("valid-token")

    @pytest.mark.asyncio
    async def test_validate_token_raises_http_exception_on_authentication_error(self):
        """Test that AuthenticationException is converted to HTTPException 401."""
        mock_provider = AsyncMock()
        mock_provider.validate_token.side_effect = AuthenticationException("Invalid token")

        authenticator = HTTPAuthenticator(mock_provider)

        with pytest.raises(HTTPException) as exc_info:
            await authenticator._validate_token("invalid-token")

        assert exc_info.value.status_code == 401
        assert "Invalid token" in exc_info.value.detail
        assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}

    @pytest.mark.asyncio
    async def test_validate_token_chains_authentication_exception(self):
        """Test that HTTPException chains the original AuthenticationException."""
        mock_provider = AsyncMock()
        original_error = AuthenticationException("Token expired")
        mock_provider.validate_token.side_effect = original_error

        authenticator = HTTPAuthenticator(mock_provider)

        with pytest.raises(HTTPException) as exc_info:
            await authenticator._validate_token("expired-token")

        assert exc_info.value.__cause__ is original_error


class TestBaseFastAPIAuthenticatorRequireRealmRole:
    """Test require_realm_role method via HTTPAuthenticator."""

    def test_require_realm_role_creates_dependency(self):
        """Test that require_realm_role returns a callable dependency."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        dependency = authenticator.require_realm_role("admin")

        assert callable(dependency)

    @pytest.mark.asyncio
    async def test_require_realm_role_dependency_success(self):
        """Test that role dependency succeeds when user has role."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=["admin"],
            client_roles={},
        )

        dependency = authenticator.require_realm_role("admin")

        # Manually call the dependency (simulating FastAPI DI)
        result = await dependency(mock_user)

        assert result is mock_user

    @pytest.mark.asyncio
    async def test_require_realm_role_dependency_raises_on_missing_role(self):
        """Test that role dependency raises HTTPException 403 when user lacks role."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=["user"],  # Missing 'admin' role
            client_roles={},
        )

        dependency = authenticator.require_realm_role("admin")

        with pytest.raises(HTTPException) as exc_info:
            await dependency(mock_user)

        assert exc_info.value.status_code == 403


class TestBaseFastAPIAuthenticatorRequireClientRole:
    """Test require_client_role method via HTTPAuthenticator."""

    def test_require_client_role_creates_dependency(self):
        """Test that require_client_role returns a callable dependency."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        dependency = authenticator.require_client_role("client1", "role1")

        assert callable(dependency)

    @pytest.mark.asyncio
    async def test_require_client_role_dependency_success(self):
        """Test that client role dependency succeeds when user has role."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={"client1": ["role1", "role2"]},
        )

        dependency = authenticator.require_client_role("client1", "role1")

        result = await dependency(mock_user)

        assert result is mock_user

    @pytest.mark.asyncio
    async def test_require_client_role_dependency_raises_on_missing_role(self):
        """Test that client role dependency raises HTTPException 403 when user lacks role."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={"client1": ["role2"]},  # Missing 'role1'
        )

        dependency = authenticator.require_client_role("client1", "role1")

        with pytest.raises(HTTPException) as exc_info:
            await dependency(mock_user)

        assert exc_info.value.status_code == 403


class TestHTTPAuthenticatorInitialization:
    """Test HTTPAuthenticator initialization."""

    def test_init_creates_http_bearer_schemes(self):
        """Test that __init__ creates HTTPBearer schemes."""
        mock_provider = MagicMock()
        authenticator = HTTPAuthenticator(mock_provider)

        assert authenticator._http_bearer is not None
        assert authenticator._http_bearer_optional is not None


class TestHTTPAuthenticatorGetCurrentUser:
    """Test get_current_user method."""

    @pytest.mark.asyncio
    async def test_get_current_user_success(self):
        """Test successful user authentication via HTTP Bearer."""
        mock_provider = AsyncMock()
        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={},
        )
        mock_provider.validate_token.return_value = mock_user

        authenticator = HTTPAuthenticator(mock_provider)

        # Simulate FastAPI HTTPAuthorizationCredentials
        mock_credentials = MagicMock()
        mock_credentials.credentials = "valid-token"

        result = await authenticator.get_current_user(credentials=mock_credentials)

        assert result is mock_user
        mock_provider.validate_token.assert_called_once_with("valid-token")

    @pytest.mark.asyncio
    async def test_get_current_user_raises_http_exception_on_invalid_token(self):
        """Test that invalid token raises HTTPException 401."""
        mock_provider = AsyncMock()
        mock_provider.validate_token.side_effect = AuthenticationException("Invalid token")

        authenticator = HTTPAuthenticator(mock_provider)

        mock_credentials = MagicMock()
        mock_credentials.credentials = "invalid-token"

        with pytest.raises(HTTPException) as exc_info:
            await authenticator.get_current_user(credentials=mock_credentials)

        assert exc_info.value.status_code == 401


class TestHTTPAuthenticatorGetCurrentUserOptional:
    """Test get_current_user_optional method."""

    @pytest.mark.asyncio
    async def test_get_current_user_optional_success(self):
        """Test optional authentication with valid credentials."""
        mock_provider = AsyncMock()
        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={},
        )
        mock_provider.validate_token.return_value = mock_user

        authenticator = HTTPAuthenticator(mock_provider)

        mock_credentials = MagicMock()
        mock_credentials.credentials = "valid-token"

        result = await authenticator.get_current_user_optional(credentials=mock_credentials)

        assert result is mock_user

    @pytest.mark.asyncio
    async def test_get_current_user_optional_returns_none_when_no_credentials(self):
        """Test that optional authentication returns None when no credentials."""
        mock_provider = AsyncMock()
        authenticator = HTTPAuthenticator(mock_provider)

        result = await authenticator.get_current_user_optional(credentials=None)

        assert result is None
        mock_provider.validate_token.assert_not_called()


class TestWebSocketAuthenticatorGetCurrentUser:
    """Test WebSocketAuthenticator get_current_user method."""

    @pytest.mark.asyncio
    async def test_get_current_user_success(self):
        """Test successful user authentication via WebSocket query parameter."""
        mock_provider = AsyncMock()
        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={},
        )
        mock_provider.validate_token.return_value = mock_user

        authenticator = WebSocketAuthenticator(mock_provider)

        result = await authenticator.get_current_user(token="valid-token")

        assert result is mock_user
        mock_provider.validate_token.assert_called_once_with("valid-token")

    @pytest.mark.asyncio
    async def test_get_current_user_raises_http_exception_on_invalid_token(self):
        """Test that invalid token raises HTTPException 401."""
        mock_provider = AsyncMock()
        mock_provider.validate_token.side_effect = AuthenticationException("Invalid token")

        authenticator = WebSocketAuthenticator(mock_provider)

        with pytest.raises(HTTPException) as exc_info:
            await authenticator.get_current_user(token="invalid-token")

        assert exc_info.value.status_code == 401


class TestWebSocketAuthenticatorGetCurrentUserOptional:
    """Test WebSocketAuthenticator get_current_user_optional method."""

    @pytest.mark.asyncio
    async def test_get_current_user_optional_success(self):
        """Test optional authentication with valid token."""
        mock_provider = AsyncMock()
        mock_user = User(
            id="user-123",
            username="testuser",
            realm_roles=[],
            client_roles={},
        )
        mock_provider.validate_token.return_value = mock_user

        authenticator = WebSocketAuthenticator(mock_provider)

        result = await authenticator.get_current_user_optional(token="valid-token")

        assert result is mock_user

    @pytest.mark.asyncio
    async def test_get_current_user_optional_returns_none_when_no_token(self):
        """Test that optional authentication returns None when no token."""
        mock_provider = AsyncMock()
        authenticator = WebSocketAuthenticator(mock_provider)

        result = await authenticator.get_current_user_optional(token=None)

        assert result is None
        mock_provider.validate_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_current_user_optional_returns_none_when_empty_token(self):
        """Test that optional authentication returns None when empty token."""
        mock_provider = AsyncMock()
        authenticator = WebSocketAuthenticator(mock_provider)

        result = await authenticator.get_current_user_optional(token="")

        assert result is None
        mock_provider.validate_token.assert_not_called()
        result = await authenticator.get_current_user_optional(token="")

        assert result is None
        mock_provider.validate_token.assert_not_called()
