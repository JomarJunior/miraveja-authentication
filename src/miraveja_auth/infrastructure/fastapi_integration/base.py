from typing import Callable

from fastapi import Depends, HTTPException, status

from miraveja_auth.domain import AuthenticationException, IAuthenticator, IOAuth2Provider, User


class BaseFastAPIAuthenticator(IAuthenticator):
    """Base class for FastAPI authenticators.

    Provides common role validation logic.
    """

    def __init__(self, provider: IOAuth2Provider):
        """Initialize authenticator.

        Args:
            provider: OAuth2 provider for token validation.
        """
        self._provider = provider

    async def _validate_token(self, token: str) -> User:
        """Validate token and return user.

        Args:
            token: JWT access token.

        Returns:
            Authenticated User.

        Raises:
            HTTPException: 401 if validation fails.
        """
        try:
            return await self._provider.validate_token(token)
        except AuthenticationException as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=e.message,
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    def _create_role_dependency(
        self,
        get_user_function: Callable,
        check_role_function: Callable[[User], None],
    ) -> Callable:
        """Create a role-checking dependency.

        Args:
            get_user_func: Function to get current user.
            check_role_func: Function to check if user has required role.

        Returns:
            FastAPI dependency function.
        """

        async def role_dependency(user: User = Depends(get_user_function)) -> User:
            try:
                check_role_function(user)
                return user
            except AuthenticationException as e:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=e.message,
                ) from e

        return role_dependency

    def require_realm_role(self, role_name: str) -> Callable:
        """Create dependency requiring a realm role.

        Args:
            role: Required realm role name.

        Returns:
            FastAPI dependency function.
        """
        return self._create_role_dependency(
            get_user_function=self.get_current_user,
            check_role_function=lambda user: user.require_realm_role(  # Not recursive, this is User's method
                role_name,
            ),
        )

    def require_client_role(self, client_id: str, role_name: str) -> Callable:
        """Create dependency requiring a client role.

        Args:
            client: Client ID.
            role: Required client role name.

        Returns:
            FastAPI dependency function.
        """
        return self._create_role_dependency(
            get_user_function=self.get_current_user,
            check_role_function=lambda user: user.require_client_role(  # Not recursive, this is User's method
                client_id, role_name
            ),
        )
