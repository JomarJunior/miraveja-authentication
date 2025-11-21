"""Unit tests for MockOAuth2Provider."""

import pytest

from miraveja_auth.domain import TokenExpiredException, TokenInvalidException, User
from miraveja_auth.infrastructure.testing import MockOAuth2Provider


class TestMockOAuth2ProviderInitialization:
    """Test MockOAuth2Provider initialization."""

    def test_init_creates_empty_state(self):
        """Test that __init__ creates empty internal state."""
        provider = MockOAuth2Provider()

        assert provider._users == {}
        assert provider._tokens == {}
        assert provider._failure_mode is None


class TestMockOAuth2ProviderAddUser:
    """Test add_user method."""

    def test_add_user_with_all_parameters(self):
        """Test adding a user with all parameters."""
        provider = MockOAuth2Provider()

        provider.add_user(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            realm_roles=["admin", "user"],
            client_roles={"client1": ["role1", "role2"]},
        )

        assert "user-123" in provider._users
        user = provider._users["user-123"]
        assert user.id == "user-123"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.realm_roles == ["admin", "user"]
        assert user.client_roles == {"client1": ["role1", "role2"]}

    def test_add_user_with_minimal_parameters(self):
        """Test adding a user with only user_id."""
        provider = MockOAuth2Provider()

        provider.add_user(user_id="user-123")

        assert "user-123" in provider._users
        user = provider._users["user-123"]
        assert user.id == "user-123"
        assert user.username == "user-123"  # Defaults to user_id
        assert user.email is None
        assert user.realm_roles == []
        assert user.client_roles == {}

    def test_add_user_defaults_username_to_user_id(self):
        """Test that username defaults to user_id when not provided."""
        provider = MockOAuth2Provider()

        provider.add_user(user_id="user-456")

        user = provider._users["user-456"]
        assert user.username == "user-456"

    def test_add_user_can_override_existing_user(self):
        """Test that adding a user with same ID overwrites the previous one."""
        provider = MockOAuth2Provider()

        provider.add_user(user_id="user-123", username="first")
        provider.add_user(user_id="user-123", username="second")

        user = provider._users["user-123"]
        assert user.username == "second"


class TestMockOAuth2ProviderSetTokenForUser:
    """Test set_token_for_user method."""

    def test_set_token_for_user_with_provided_token(self):
        """Test setting a specific token for a user."""
        provider = MockOAuth2Provider()

        token = provider.set_token_for_user("user-123", "custom-token")

        assert token == "custom-token"
        assert provider._tokens["custom-token"] == "user-123"

    def test_set_token_for_user_generates_token_when_none(self):
        """Test that token is generated when not provided."""
        provider = MockOAuth2Provider()

        token = provider.set_token_for_user("user-123", None)

        assert token is not None
        assert token.startswith("mock-token-user-123-")
        assert provider._tokens[token] == "user-123"

    def test_set_token_for_user_returns_generated_token(self):
        """Test that generated token is returned."""
        provider = MockOAuth2Provider()

        token = provider.set_token_for_user("user-456", None)

        assert isinstance(token, str)
        assert len(token) > 0
        assert provider._tokens[token] == "user-456"

    def test_set_token_for_user_multiple_tokens_same_user(self):
        """Test setting multiple tokens for the same user."""
        provider = MockOAuth2Provider()

        token1 = provider.set_token_for_user("user-123", "token1")
        token2 = provider.set_token_for_user("user-123", "token2")

        assert provider._tokens["token1"] == "user-123"
        assert provider._tokens["token2"] == "user-123"


class TestMockOAuth2ProviderValidateToken:
    """Test validate_token method."""

    @pytest.mark.asyncio
    async def test_validate_token_success(self):
        """Test successful token validation."""
        provider = MockOAuth2Provider()

        provider.add_user(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
        )
        token = provider.set_token_for_user("user-123", "valid-token")

        user = await provider.validate_token(token)

        assert isinstance(user, User)
        assert user.id == "user-123"
        assert user.username == "testuser"
        assert user.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_validate_token_failure_mode_expired(self):
        """Test that expired failure mode raises TokenExpiredException."""
        provider = MockOAuth2Provider()
        provider._failure_mode = "expired"

        with pytest.raises(TokenExpiredException):
            await provider.validate_token("any-token")

    @pytest.mark.asyncio
    async def test_validate_token_failure_mode_invalid(self):
        """Test that invalid failure mode raises TokenInvalidException."""
        provider = MockOAuth2Provider()
        provider._failure_mode = "invalid"

        with pytest.raises(TokenInvalidException):
            await provider.validate_token("any-token")

    @pytest.mark.asyncio
    async def test_validate_token_raises_when_token_not_found(self):
        """Test that validation raises TokenInvalidException when token not found."""
        provider = MockOAuth2Provider()

        with pytest.raises(TokenInvalidException):
            await provider.validate_token("nonexistent-token")

    @pytest.mark.asyncio
    async def test_validate_token_raises_when_user_not_found(self):
        """Test that validation raises TokenInvalidException when user not found."""
        provider = MockOAuth2Provider()

        provider.set_token_for_user("user-123", "orphan-token")
        # User not added to _users

        with pytest.raises(TokenInvalidException):
            await provider.validate_token("orphan-token")

    @pytest.mark.asyncio
    async def test_validate_token_with_complete_user_data(self):
        """Test validation returns complete user data."""
        provider = MockOAuth2Provider()

        provider.add_user(
            user_id="user-123",
            username="testuser",
            email="test@example.com",
            realm_roles=["admin", "user"],
            client_roles={"client1": ["role1", "role2"]},
        )
        token = provider.set_token_for_user("user-123", "token")

        user = await provider.validate_token(token)

        assert user.realm_roles == ["admin", "user"]
        assert user.client_roles == {"client1": ["role1", "role2"]}


class TestMockOAuth2ProviderIntegration:
    """Test MockOAuth2Provider integration scenarios."""

    @pytest.mark.asyncio
    async def test_full_workflow_add_user_and_validate(self):
        """Test complete workflow: add user, set token, validate."""
        provider = MockOAuth2Provider()

        # Add user
        provider.add_user(
            user_id="user-123",
            username="testuser",
            realm_roles=["admin"],
        )

        # Set token
        token = provider.set_token_for_user("user-123", None)

        # Validate token
        user = await provider.validate_token(token)

        assert user.id == "user-123"
        assert user.username == "testuser"
        assert user.realm_roles == ["admin"]

    @pytest.mark.asyncio
    async def test_multiple_users_with_different_tokens(self):
        """Test handling multiple users with different tokens."""
        provider = MockOAuth2Provider()

        # Add multiple users
        provider.add_user(user_id="user-1", username="user1")
        provider.add_user(user_id="user-2", username="user2")

        # Set different tokens
        token1 = provider.set_token_for_user("user-1", "token1")
        token2 = provider.set_token_for_user("user-2", "token2")

        # Validate each token
        user1 = await provider.validate_token(token1)
        user2 = await provider.validate_token(token2)

        assert user1.username == "user1"
        assert user2.username == "user2"
