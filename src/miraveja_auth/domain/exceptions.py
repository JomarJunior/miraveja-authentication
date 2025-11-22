from typing import Optional


class AuthenticationException(Exception):
    """Base exception for authentication errors."""

    def __init__(self, message: str, detail: Optional[str] = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)


class TokenExpiredException(AuthenticationException):
    """Exception raised when an authentication token has expired."""

    def __init__(self, expires_at: Optional[int] = None, ttl: Optional[int] = None):
        super().__init__("The authentication token has expired.")
        self.ttl = ttl
        self.expires_at = expires_at


class TokenInvalidException(AuthenticationException):
    """Exception raised when an the token signature or structure is invalid."""

    def __init__(self, message: Optional[str] = None) -> None:
        if message is None:
            super().__init__("The authentication token is invalid.")
        else:
            super().__init__(f"The authentication token is invalid: {message}")


class AuthorizationException(AuthenticationException):
    """Exception raised when a user is not authorized to perform an action."""

    def __init__(self, action: Optional[str] = None, required_role: Optional[str] = None):
        message = "User is not authorized to perform this action."
        if action:
            message += f" Action: {action}"
        if required_role:
            message += f" Required Role: {required_role}"
        super().__init__(message)
        self.action = action
        self.required_role = required_role


class ConfigurationException(Exception):
    """Exception raised for configuration errors."""

    def __init__(self, field: str, message: Optional[str] = None):
        if message is None:
            message = "Configuration error"
        super().__init__(f"{field}: {message}")
        self.field = field
