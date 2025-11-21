"""Unit tests for domain exceptions."""

import pytest

from miraveja_auth.domain.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConfigurationException,
    TokenExpiredException,
    TokenInvalidException,
)


class TestAuthenticationException:
    """Test suite for AuthenticationException base class."""

    def test_create_with_message_only(self):
        """Test creating exception with message only."""
        exc = AuthenticationException("Authentication failed")
        assert exc.message == "Authentication failed"
        assert exc.detail is None
        assert str(exc) == "Authentication failed"

    def test_create_with_message_and_detail(self):
        """Test creating exception with message and detail."""
        exc = AuthenticationException("Authentication failed", detail="Invalid credentials")
        assert exc.message == "Authentication failed"
        assert exc.detail == "Invalid credentials"
        assert str(exc) == "Authentication failed"

    def test_create_with_detail_as_kwarg(self):
        """Test creating exception with detail as keyword argument."""
        exc = AuthenticationException("Auth error", detail="Additional context")
        assert exc.message == "Auth error"
        assert exc.detail == "Additional context"

    def test_inheritance(self):
        """Test that AuthenticationException inherits from Exception."""
        exc = AuthenticationException("Test")
        assert isinstance(exc, Exception)


class TestTokenExpiredException:
    """Test suite for TokenExpiredException."""

    def test_create_without_parameters(self):
        """Test creating exception without optional parameters."""
        exc = TokenExpiredException()
        assert exc.message == "The authentication token has expired."
        assert exc.detail is None
        assert exc.expires_at is None
        assert exc.ttl is None
        assert str(exc) == "The authentication token has expired."

    def test_create_with_expires_at(self):
        """Test creating exception with expires_at timestamp."""
        exc = TokenExpiredException(expires_at=1700000000)
        assert exc.message == "The authentication token has expired."
        assert exc.expires_at == 1700000000
        assert exc.ttl is None

    def test_create_with_ttl(self):
        """Test creating exception with time-to-live."""
        exc = TokenExpiredException(ttl=3600)
        assert exc.message == "The authentication token has expired."
        assert exc.ttl == 3600
        assert exc.expires_at is None

    def test_create_with_both_parameters(self):
        """Test creating exception with both expires_at and ttl."""
        exc = TokenExpiredException(expires_at=1700000000, ttl=3600)
        assert exc.expires_at == 1700000000
        assert exc.ttl == 3600

    def test_create_with_parameters_as_kwargs(self):
        """Test creating exception with parameters as keyword arguments."""
        exc = TokenExpiredException(ttl=7200, expires_at=1700003600)
        assert exc.ttl == 7200
        assert exc.expires_at == 1700003600

    def test_inheritance(self):
        """Test that TokenExpiredException inherits from AuthenticationException."""
        exc = TokenExpiredException()
        assert isinstance(exc, AuthenticationException)
        assert isinstance(exc, Exception)


class TestTokenInvalidException:
    """Test suite for TokenInvalidException."""

    def test_create_without_parameters(self):
        """Test creating exception without parameters."""
        exc = TokenInvalidException()
        assert exc.message == "The authentication token is invalid."
        assert exc.detail is None
        assert str(exc) == "The authentication token is invalid."

    def test_has_fixed_message(self):
        """Test that exception has fixed message."""
        exc1 = TokenInvalidException()
        exc2 = TokenInvalidException()
        assert exc1.message == exc2.message
        assert exc1.message == "The authentication token is invalid."

    def test_inheritance(self):
        """Test that TokenInvalidException inherits from AuthenticationException."""
        exc = TokenInvalidException()
        assert isinstance(exc, AuthenticationException)
        assert isinstance(exc, Exception)


class TestAuthorizationException:
    """Test suite for AuthorizationException."""

    def test_create_without_parameters(self):
        """Test creating exception without optional parameters."""
        exc = AuthorizationException()
        assert exc.message == "User is not authorized to perform this action."
        assert exc.action is None
        assert exc.required_role is None
        assert str(exc) == "User is not authorized to perform this action."

    def test_create_with_action_only(self):
        """Test creating exception with action only."""
        exc = AuthorizationException(action="delete_user")
        assert "User is not authorized to perform this action." in exc.message
        assert " Action: delete_user" in exc.message
        assert exc.action == "delete_user"
        assert exc.required_role is None

    def test_create_with_required_role_only(self):
        """Test creating exception with required role only."""
        exc = AuthorizationException(required_role="admin")
        assert "User is not authorized to perform this action." in exc.message
        assert " Required Role: admin" in exc.message
        assert exc.action is None
        assert exc.required_role == "admin"

    def test_create_with_both_parameters(self):
        """Test creating exception with both action and required role."""
        exc = AuthorizationException(action="modify_settings", required_role="superadmin")
        assert "User is not authorized to perform this action." in exc.message
        assert " Action: modify_settings" in exc.message
        assert " Required Role: superadmin" in exc.message
        assert exc.action == "modify_settings"
        assert exc.required_role == "superadmin"

    def test_create_with_parameters_as_kwargs(self):
        """Test creating exception with parameters as keyword arguments."""
        exc = AuthorizationException(required_role="editor", action="publish")
        assert exc.action == "publish"
        assert exc.required_role == "editor"
        assert " Action: publish" in exc.message
        assert " Required Role: editor" in exc.message

    def test_message_format_consistency(self):
        """Test that message format is consistent."""
        exc1 = AuthorizationException(action="test")
        exc2 = AuthorizationException(required_role="test")
        exc3 = AuthorizationException(action="test1", required_role="test2")

        assert exc1.message.startswith("User is not authorized to perform this action.")
        assert exc2.message.startswith("User is not authorized to perform this action.")
        assert exc3.message.startswith("User is not authorized to perform this action.")

    def test_inheritance(self):
        """Test that AuthorizationException inherits from AuthenticationException."""
        exc = AuthorizationException()
        assert isinstance(exc, AuthenticationException)
        assert isinstance(exc, Exception)


class TestConfigurationException:
    """Test suite for ConfigurationException."""

    def test_create_with_field_only(self):
        """Test creating exception with field name only."""
        exc = ConfigurationException(field="issuer_url")
        assert exc.field == "issuer_url"
        assert str(exc) == "issuer_url: Configuration error"

    def test_create_with_field_and_message(self):
        """Test creating exception with field and message."""
        exc = ConfigurationException(field="client_id", message="Client ID is required")
        assert exc.field == "client_id"
        assert str(exc) == "client_id: Client ID is required"

    def test_create_with_message_as_kwarg(self):
        """Test creating exception with message as keyword argument."""
        exc = ConfigurationException(field="audience", message="Invalid audience format")
        assert exc.field == "audience"
        assert "audience: Invalid audience format" == str(exc)

    def test_message_format(self):
        """Test that message format follows pattern: field: message."""
        exc = ConfigurationException(field="test_field", message="Test message")
        message = str(exc)
        assert message.startswith("test_field:")
        assert "Test message" in message

    def test_inheritance(self):
        """Test that ConfigurationException inherits from Exception (not AuthenticationException)."""
        exc = ConfigurationException(field="test")
        assert isinstance(exc, Exception)
        assert not isinstance(exc, AuthenticationException)


class TestExceptionInteroperability:
    """Test suite for exception interoperability and edge cases."""

    def test_all_exceptions_are_catchable_as_base_exception(self):
        """Test that all exceptions can be caught as base Exception."""
        exceptions = [
            AuthenticationException("test"),
            TokenExpiredException(),
            TokenInvalidException(),
            AuthorizationException(),
            ConfigurationException(field="test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, Exception)

    def test_authentication_related_exceptions_share_base(self):
        """Test that authentication-related exceptions share common base."""
        auth_exceptions = [
            AuthenticationException("test"),
            TokenExpiredException(),
            TokenInvalidException(),
            AuthorizationException(),
        ]

        for exc in auth_exceptions:
            assert isinstance(exc, AuthenticationException)

    def test_exceptions_can_be_raised_and_caught(self):
        """Test that exceptions can be raised and caught normally."""
        with pytest.raises(TokenExpiredException) as exc_info:
            raise TokenExpiredException(expires_at=1700000000)
        assert exc_info.value.expires_at == 1700000000

        with pytest.raises(AuthorizationException) as exc_info:
            raise AuthorizationException(required_role="admin")
        assert exc_info.value.required_role == "admin"

        with pytest.raises(ConfigurationException) as exc_info:
            raise ConfigurationException(field="test", message="test message")
        assert exc_info.value.field == "test"

    def test_catching_base_authentication_exception(self):
        """Test catching specific exceptions as AuthenticationException base."""
        with pytest.raises(AuthenticationException):
            raise TokenExpiredException()

        with pytest.raises(AuthenticationException):
            raise TokenInvalidException()

        with pytest.raises(AuthenticationException):
            raise AuthorizationException()
