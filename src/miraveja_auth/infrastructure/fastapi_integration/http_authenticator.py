from typing import Any, Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from miraveja_auth.domain import IOAuth2Provider, User
from miraveja_auth.infrastructure.fastapi_integration.base import BaseFastAPIAuthenticator


class HTTPAuthenticator(BaseFastAPIAuthenticator):
    """HTTP Bearer token authenticator for FastAPI.

    Extracts JWT tokens from Authorization header (Bearer scheme).
    Use for standard HTTP REST endpoints.
    """

    def __init__(self, provider: IOAuth2Provider):
        """Initialize HTTP authenticator.

        Args:
            provider: OAuth2 provider for token validation.
        """
        super().__init__(provider)
        self._http_bearer = HTTPBearer()
        self._http_bearer_optional = HTTPBearer(auto_error=False)

    async def get_current_user(
        self,
        *args: Any,
        credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
        **kwargs: Any,
    ) -> User:
        """Get current authenticated user from HTTP Authorization header.

        FastAPI dependency for protected endpoints.

        Args:
            credentials: HTTP Bearer credentials from Authorization header.

        Returns:
            Authenticated User.

        Raises:
            HTTPException: 401 if authentication fails.
        """
        token = credentials.credentials
        return await self._validate_token(token)

    async def get_current_user_optional(
        self,
        *args: Any,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
        **kwargs: Any,
    ) -> Optional[User]:
        """Get current user from HTTP Authorization header (optional).

        FastAPI dependency for endpoints with optional authentication.

        Args:
            credentials: Optional HTTP Bearer credentials.

        Returns:
            Authenticated User or None.
        """
        if credentials is None:
            return None

        token = credentials.credentials
        return await self._validate_token(token)
