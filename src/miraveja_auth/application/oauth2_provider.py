from datetime import datetime, timezone

import jwt

from miraveja_auth.application.configuration import OAuth2Configuration
from miraveja_auth.domain import (
    AuthenticationException,
    IClaimsParser,
    IOAuth2Provider,
    IOIDCDiscoveryService,
    TokenExpiredException,
    TokenInvalidException,
    User,
)


class OAuth2Provider(IOAuth2Provider):
    """OAuth2/OIDC provider - Token validation use case.

    This class orchestrates token validation by:
    1. Checking token expiration and TTL
    2. Verifying JWT signature (offline with static key or online with JWKS)
    3. Parsing claims using provider-specific parser
    4. Creating User from claims (claims extract their own roles)

    Attributes:
        config: OAuth2 configuration.
        discovery_service: Service for OIDC discovery and JWKS.
        claims_parser: Parser for converting JWT payload to provider-specific Claims.
    """

    def __init__(
        self,
        config: OAuth2Configuration,
        discovery_service: IOIDCDiscoveryService,
        claims_parser: IClaimsParser,
    ):
        """Initialize provider.

        Args:
            config: OAuth2 configuration.
            discovery_service: Service for OIDC discovery and JWKS.
            claims_parser: Parser for converting JWT payload to provider-specific Claims.
        """
        self._config = config
        self._discovery_service = discovery_service
        self._claims_parser = claims_parser

    async def validate_token(self, token: str) -> User:
        """Validate JWT token and return authenticated user.

        Args:
            token: JWT access token.

        Returns:
            Authenticated User with roles.

        Raises:
            TokenExpiredError: Token has expired.
            TokenInvalidError: Token is invalid.
            AuthenticationError: Other validation errors.

        Examples:
            >>> user = await oauth2_provider.validate_token("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
            >>> print(user.id, user.username, user.realm_roles, user.client_roles)
        """
        try:
            # Decode without verification first to check expiration
            unverified_payload = jwt.decode(
                token,
                options={"verify_signature": False},
            )

            # Check expiration and TTL
            expiration: int = unverified_payload.get("exp", 0)
            current_time = int(datetime.now(timezone.utc).timestamp())

            if expiration <= current_time:
                raise TokenExpiredException(
                    expires_at=expiration,
                    ttl=0,
                )

            ttl = expiration - current_time
            if ttl < self._config.token_minimum_ttl_seconds:
                raise TokenExpiredException(
                    expires_at=expiration,
                    ttl=ttl,
                )

            # Verify signature and decode
            if self._config.public_key:
                # Offline validation with static key
                verified_payload = jwt.decode(
                    token,
                    self._config.public_key,
                    algorithms=[self._config.token_verification_algorithm],
                    audience=self._config.client_id,
                    issuer=self._config.issuer,
                )
            else:
                # Online validation with JWKS
                signing_key = await self._discovery_service.get_signing_key(token)
                verified_payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=[self._config.token_verification_algorithm],
                    audience=self._config.client_id,
                    issuer=self._config.issuer,
                )

            # Parse claims using provider-specific parser
            claims = self._claims_parser.parse(verified_payload)

            # Create user from claims
            user = User.from_claims(claims)

            return user
        except TokenExpiredException:
            # Re-raise TokenExpiredException as-is (from manual validation checks)
            raise
        except jwt.ExpiredSignatureError as e:
            raise TokenExpiredException() from e
        except jwt.InvalidTokenError as e:
            raise TokenInvalidException(str(e)) from e
        except Exception as e:
            raise AuthenticationException(f"Token validation failed: {str(e)}") from e
