from typing import Optional

from fastapi import Query

from miraveja_auth.domain import User
from miraveja_auth.infrastructure.fastapi_integration.base import BaseFastAPIAuthenticator


class WebSocketAuthenticator(BaseFastAPIAuthenticator):
    """WebSocket query parameter authenticator for FastAPI.

    Extracts JWT tokens from query string (?token=...).
    Use for WebSocket connections where Authorization headers aren't available.
    """

    async def get_current_user(
        self,
        *args,
        token: str = Query(..., description="JWT access token"),
        **kwargs,
    ) -> User:
        """Get current user from WebSocket query parameter.

        FastAPI dependency for protected WebSocket endpoints.

        Args:
            token: JWT token from query string.

        Returns:
            Authenticated User.

        Raises:
            HTTPException: 401 if authentication fails.
        """
        return await self._validate_token(token)

    async def get_current_user_optional(
        self,
        *args,
        token: Optional[str] = Query(None, description="JWT access token"),
        **kwargs,
    ) -> Optional[User]:
        """Get current user from WebSocket query parameter (optional).

        FastAPI dependency for WebSocket endpoints with optional authentication.

        Args:
            token: Optional JWT token from query string.

        Returns:
            Authenticated User or None if not authenticated.
        """
        if not token:
            return None

        return await self._validate_token(token)
