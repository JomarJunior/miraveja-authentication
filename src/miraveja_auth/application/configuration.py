import os
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class OAuth2Configuration(BaseModel):

    issuer: str = Field(..., description="OIDC Issuer URL")
    client_id: str = Field(..., description="OAuth2 Client ID")
    client_secret: Optional[str] = Field(default=None, description="OAuth2 Client Secret")
    verify_ssl: bool = Field(default=True, description="Whether to verify SSL certificates")
    public_key: Optional[str] = Field(default=None, description="Public key for token verification (if applicable)")
    token_verification_algorithm: str = Field(default="RS256", description="Algorithm used for JWT token verification")
    token_minimum_ttl_seconds: int = Field(default=60, description="Minimum TTL for tokens in seconds")

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v: str) -> str:
        """Validate and normalizer issuer URL.

        **Rules**:
            - Must start with http:// or https://
            - Must not end with a trailing slash (stripped if present)
        """
        if not v.startswith(("http://", "https://")):
            raise ValueError("Issuer must be a valid HTTP(s) URL")
        return v.rstrip("/")  # Remove trailing slash if present

    @classmethod
    def from_env(cls) -> "OAuth2Configuration":
        """Create configuration from environment variables.

        Environment variables:
            OAUTH2_ISSUER: Required
            OAUTH2_CLIENT_ID: Required
            OAUTH2_CLIENT_SECRET: Optional
            OAUTH2_VERIFY_SSL: Optional (default: true)
            OAUTH2_PUBLIC_KEY: Optional
            OAUTH2_TOKEN_ALGORITHM: Optional (default: RS256)
            OAUTH2_TOKEN_MIN_TTL: Optional (default: 60)

        Returns:
            OAuth2Configuration instance.

        Raises:
            ConfigurationError: Required variables missing.
        """
        data: Dict[str, Any] = {}

        issuer = os.getenv("OAUTH2_ISSUER")
        if not issuer:
            raise ValueError("OAUTH2_ISSUER environment variable is required")
        data["issuer"] = issuer

        client_id = os.getenv("OAUTH2_CLIENT_ID")
        if not client_id:
            raise ValueError("OAUTH2_CLIENT_ID environment variable is required")
        data["client_id"] = client_id

        client_secret = os.getenv("OAUTH2_CLIENT_SECRET")
        if client_secret:
            data["client_secret"] = client_secret

        verify_ssl = os.getenv("OAUTH2_VERIFY_SSL")
        if verify_ssl is not None:
            data["verify_ssl"] = verify_ssl.lower() in ("1", "true", "yes")

        public_key = os.getenv("OAUTH2_PUBLIC_KEY")
        if public_key:
            data["public_key"] = public_key

        token_algorithm = os.getenv("OAUTH2_TOKEN_ALGORITHM")
        if token_algorithm:
            data["token_verification_algorithm"] = token_algorithm

        token_min_ttl = os.getenv("OAUTH2_TOKEN_MIN_TTL")
        if token_min_ttl:
            try:
                data["token_minimum_ttl_seconds"] = int(token_min_ttl)
            except ValueError as e:
                raise ValueError("OAUTH2_TOKEN_MIN_TTL must be an integer") from e

        return cls(**data)
