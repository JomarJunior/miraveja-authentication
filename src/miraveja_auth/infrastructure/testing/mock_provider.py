from datetime import datetime, timezone
from typing import Dict, List, Optional

from miraveja_auth.domain import IOAuth2Provider, TokenExpiredException, TokenInvalidException, User


class MockOAuth2Provider(IOAuth2Provider):
    def __init__(self) -> None:
        """Initialize the mock OAuth2 provider."""
        self._users: Dict[str, User] = {}
        self._tokens: Dict[str, str] = {}  # token -> user_id mapping
        self._failure_mode: Optional[str] = None

    def add_user(
        self,
        user_id: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        realm_roles: Optional[List[str]] = None,
        client_roles: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """Add a test user.

        Args:
            user_id: User ID.
            username: Username (defaults to user_id).
            email: Email address.
            realm_roles: List of realm role names.
            client_roles: Dict of client ID -> role list.
        """
        user = User(
            id=user_id,
            username=username or user_id,
            email=email,
            realm_roles=realm_roles or [],
            client_roles=client_roles or {},
        )
        self._users[user_id] = user

    def set_token_for_user(self, user_id: str, token: Optional[str]) -> str:
        """Map a token to a user.

        Args:
            user_id: User ID to map token to.
            token: Token string (generated if not provided).

        Returns:
            Token string.
        """
        now_epoch = datetime.now(timezone.utc).timestamp()
        if token is None:
            token = f"mock-token-{user_id}-{int(now_epoch)}"

        self._tokens[token] = user_id
        return token

    async def validate_token(self, token: str) -> User:
        """Validate mock token and return user.

        Args:
            token: Token string.

        Returns:
            Mocked User.

        Raises:
            TokenExpiredError: If failure mode is 'expired'.
            TokenInvalidError: If failure mode is 'invalid' or token not found.
        """
        if self._failure_mode == "expired":
            raise TokenExpiredException()

        if self._failure_mode == "invalid":
            raise TokenInvalidException()

        user_id = self._tokens.get(token)
        if not user_id:
            raise TokenInvalidException()

        user = self._users.get(user_id)
        if not user:
            raise TokenInvalidException()

        return user
