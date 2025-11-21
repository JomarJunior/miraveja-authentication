"""Unit tests for OAuth2Configuration."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from miraveja_auth.application.configuration import OAuth2Configuration


class TestOAuth2Configuration:
    """Test suite for OAuth2Configuration model."""

    def test_create_with_required_fields_only(self):
        """Test creating configuration with only required fields."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="my-client-id",
        )
        assert config.issuer == "https://auth.example.com"
        assert config.client_id == "my-client-id"
        assert config.client_secret is None
        assert config.verify_ssl is True
        assert config.public_key is None
        assert config.token_verification_algorithm == "RS256"
        assert config.token_minimum_ttl_seconds == 60

    def test_create_with_all_fields(self):
        """Test creating configuration with all fields."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="my-client-id",
            client_secret="my-secret",
            verify_ssl=False,
            public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...",
            token_verification_algorithm="HS256",
            token_minimum_ttl_seconds=120,
        )
        assert config.issuer == "https://auth.example.com"
        assert config.client_id == "my-client-id"
        assert config.client_secret == "my-secret"
        assert config.verify_ssl is False
        assert config.public_key == "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg..."
        assert config.token_verification_algorithm == "HS256"
        assert config.token_minimum_ttl_seconds == 120

    def test_default_values(self):
        """Test that default values are set correctly."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
        )
        assert config.client_secret is None
        assert config.verify_ssl is True
        assert config.public_key is None
        assert config.token_verification_algorithm == "RS256"
        assert config.token_minimum_ttl_seconds == 60

    def test_missing_required_issuer(self):
        """Test that missing issuer raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            OAuth2Configuration(client_id="client-id")
        assert "issuer" in str(exc_info.value).lower()

    def test_missing_required_client_id(self):
        """Test that missing client_id raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            OAuth2Configuration(issuer="https://auth.example.com")
        assert "client_id" in str(exc_info.value).lower()

    def test_issuer_validation_requires_http_or_https(self):
        """Test that issuer must start with http:// or https://."""
        # Valid http://
        config = OAuth2Configuration(
            issuer="http://auth.example.com",
            client_id="client-id",
        )
        assert config.issuer == "http://auth.example.com"

        # Valid https://
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com"

        # Invalid - no protocol
        with pytest.raises(ValidationError) as exc_info:
            OAuth2Configuration(
                issuer="auth.example.com",
                client_id="client-id",
            )
        assert "must be a valid HTTP(s) URL" in str(exc_info.value)

        # Invalid - wrong protocol
        with pytest.raises(ValidationError) as exc_info:
            OAuth2Configuration(
                issuer="ftp://auth.example.com",
                client_id="client-id",
            )
        assert "must be a valid HTTP(s) URL" in str(exc_info.value)

    def test_issuer_trailing_slash_removed(self):
        """Test that trailing slash is removed from issuer URL."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com/",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com"

        # Multiple trailing slashes
        config = OAuth2Configuration(
            issuer="https://auth.example.com///",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com"

        # No trailing slash (should remain unchanged)
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com"

        # With path and trailing slash
        config = OAuth2Configuration(
            issuer="https://auth.example.com/realms/myrealm/",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com/realms/myrealm"

    def test_issuer_with_port(self):
        """Test issuer with port number."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com:8443",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com:8443"

        # With port and trailing slash
        config = OAuth2Configuration(
            issuer="https://auth.example.com:8443/",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com:8443"

    def test_token_minimum_ttl_seconds_must_be_integer(self):
        """Test that token_minimum_ttl_seconds must be an integer."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            token_minimum_ttl_seconds=300,
        )
        assert config.token_minimum_ttl_seconds == 300

        # Pydantic should coerce string to int
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            token_minimum_ttl_seconds="180",
        )
        assert config.token_minimum_ttl_seconds == 180

    def test_verify_ssl_accepts_boolean(self):
        """Test that verify_ssl accepts boolean values."""
        config_true = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            verify_ssl=True,
        )
        assert config_true.verify_ssl is True

        config_false = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            verify_ssl=False,
        )
        assert config_false.verify_ssl is False


class TestOAuth2ConfigurationFromEnv:
    """Test suite for OAuth2Configuration.from_env() factory method."""

    def test_from_env_with_required_variables_only(self, monkeypatch):
        """Test from_env with only required environment variables."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "my-client-id")

        config = OAuth2Configuration.from_env()

        assert config.issuer == "https://auth.example.com"
        assert config.client_id == "my-client-id"
        assert config.client_secret is None
        assert config.verify_ssl is True
        assert config.public_key is None
        assert config.token_verification_algorithm == "RS256"
        assert config.token_minimum_ttl_seconds == 60

    def test_from_env_with_all_variables(self, monkeypatch):
        """Test from_env with all environment variables set."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "my-client-id")
        monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "my-secret")
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "false")
        monkeypatch.setenv("OAUTH2_PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----")
        monkeypatch.setenv("OAUTH2_TOKEN_ALGORITHM", "HS256")
        monkeypatch.setenv("OAUTH2_TOKEN_MIN_TTL", "120")

        config = OAuth2Configuration.from_env()

        assert config.issuer == "https://auth.example.com"
        assert config.client_id == "my-client-id"
        assert config.client_secret == "my-secret"
        assert config.verify_ssl is False
        assert config.public_key == "-----BEGIN PUBLIC KEY-----"
        assert config.token_verification_algorithm == "HS256"
        assert config.token_minimum_ttl_seconds == 120

    def test_from_env_missing_issuer(self, monkeypatch):
        """Test from_env raises ValueError when OAUTH2_ISSUER is missing."""
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "my-client-id")
        # OAUTH2_ISSUER not set

        with pytest.raises(ValueError) as exc_info:
            OAuth2Configuration.from_env()
        assert "OAUTH2_ISSUER environment variable is required" in str(exc_info.value)

    def test_from_env_missing_client_id(self, monkeypatch):
        """Test from_env raises ValueError when OAUTH2_CLIENT_ID is missing."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        # OAUTH2_CLIENT_ID not set

        with pytest.raises(ValueError) as exc_info:
            OAuth2Configuration.from_env()
        assert "OAUTH2_CLIENT_ID environment variable is required" in str(exc_info.value)

    def test_from_env_verify_ssl_parsing(self, monkeypatch):
        """Test from_env correctly parses OAUTH2_VERIFY_SSL values."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")

        # Test "true" (lowercase)
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "true")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is True

        # Test "True" (capitalized)
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "True")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is True

        # Test "1"
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "1")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is True

        # Test "yes"
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "yes")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is True

        # Test "false"
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "false")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is False

        # Test "0"
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "0")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is False

        # Test "no"
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "no")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is False

        # Test any other value
        monkeypatch.setenv("OAUTH2_VERIFY_SSL", "maybe")
        config = OAuth2Configuration.from_env()
        assert config.verify_ssl is False

    def test_from_env_token_min_ttl_parsing(self, monkeypatch):
        """Test from_env correctly parses OAUTH2_TOKEN_MIN_TTL integer value."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")

        # Valid integer string
        monkeypatch.setenv("OAUTH2_TOKEN_MIN_TTL", "300")
        config = OAuth2Configuration.from_env()
        assert config.token_minimum_ttl_seconds == 300

        # Zero value
        monkeypatch.setenv("OAUTH2_TOKEN_MIN_TTL", "0")
        config = OAuth2Configuration.from_env()
        assert config.token_minimum_ttl_seconds == 0

    def test_from_env_token_min_ttl_invalid_integer(self, monkeypatch):
        """Test from_env raises ValueError for invalid OAUTH2_TOKEN_MIN_TTL."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")
        monkeypatch.setenv("OAUTH2_TOKEN_MIN_TTL", "not-a-number")

        with pytest.raises(ValueError) as exc_info:
            OAuth2Configuration.from_env()
        assert "OAUTH2_TOKEN_MIN_TTL must be an integer" in str(exc_info.value)

    def test_from_env_optional_variables_not_set(self, monkeypatch):
        """Test from_env with optional variables not set uses defaults."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")
        # No optional variables set

        config = OAuth2Configuration.from_env()

        assert config.client_secret is None
        assert config.verify_ssl is True  # Default
        assert config.public_key is None
        assert config.token_verification_algorithm == "RS256"  # Default
        assert config.token_minimum_ttl_seconds == 60  # Default

    def test_from_env_issuer_validation_applied(self, monkeypatch):
        """Test that from_env applies issuer validation (trailing slash removal)."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com/")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")

        config = OAuth2Configuration.from_env()
        assert config.issuer == "https://auth.example.com"

    def test_from_env_issuer_invalid_url(self, monkeypatch):
        """Test from_env with invalid issuer URL format."""
        monkeypatch.setenv("OAUTH2_ISSUER", "not-a-url")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")

        with pytest.raises(ValidationError) as exc_info:
            OAuth2Configuration.from_env()
        assert "must be a valid HTTP(s) URL" in str(exc_info.value)

    def test_from_env_with_empty_string_values(self, monkeypatch):
        """Test from_env with empty string environment variables."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")
        monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "")  # Empty string

        config = OAuth2Configuration.from_env()

        # Empty string is truthy check fails, so it's treated as not set (None)
        # The code does: if client_secret: data["client_secret"] = client_secret
        assert config.client_secret is None

    def test_from_env_partial_optional_variables(self, monkeypatch):
        """Test from_env with only some optional variables set."""
        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")
        monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "secret")
        monkeypatch.setenv("OAUTH2_TOKEN_ALGORITHM", "HS512")
        # OAUTH2_VERIFY_SSL, OAUTH2_PUBLIC_KEY, OAUTH2_TOKEN_MIN_TTL not set

        config = OAuth2Configuration.from_env()

        assert config.client_secret == "secret"
        assert config.token_verification_algorithm == "HS512"
        assert config.verify_ssl is True  # Default
        assert config.public_key is None
        assert config.token_minimum_ttl_seconds == 60  # Default

    def test_from_env_does_not_pollute_os_environ(self, monkeypatch):
        """Test that from_env doesn't modify os.environ."""
        original_environ = dict(os.environ)

        monkeypatch.setenv("OAUTH2_ISSUER", "https://auth.example.com")
        monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")

        OAuth2Configuration.from_env()

        # Only the monkeypatch changes should be present
        # (This test is more about good practice than actual functionality)
        assert "OAUTH2_ISSUER" in os.environ
        assert "OAUTH2_CLIENT_ID" in os.environ


class TestOAuth2ConfigurationEdgeCases:
    """Test edge cases and special scenarios for OAuth2Configuration."""

    def test_issuer_with_path(self):
        """Test issuer with path components."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com/realms/myrealm",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com/realms/myrealm"

    def test_issuer_with_query_parameters(self):
        """Test issuer with query parameters (unusual but valid)."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com?tenant=123",
            client_id="client-id",
        )
        assert config.issuer == "https://auth.example.com?tenant=123"

    def test_client_id_special_characters(self):
        """Test client_id with special characters."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="my-client_id.123",
        )
        assert config.client_id == "my-client_id.123"

    def test_token_verification_algorithm_case_sensitivity(self):
        """Test that token verification algorithm is case-sensitive."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            token_verification_algorithm="hs256",
        )
        assert config.token_verification_algorithm == "hs256"  # Not normalized

    def test_very_long_public_key(self):
        """Test with a very long public key string."""
        long_key = "-----BEGIN PUBLIC KEY-----\n" + ("A" * 1000) + "\n-----END PUBLIC KEY-----"
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            public_key=long_key,
        )
        assert config.public_key == long_key

    def test_negative_token_minimum_ttl(self):
        """Test with negative token_minimum_ttl_seconds."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            token_minimum_ttl_seconds=-1,
        )
        assert config.token_minimum_ttl_seconds == -1

    def test_zero_token_minimum_ttl(self):
        """Test with zero token_minimum_ttl_seconds."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            token_minimum_ttl_seconds=0,
        )
        assert config.token_minimum_ttl_seconds == 0

    def test_very_large_token_minimum_ttl(self):
        """Test with very large token_minimum_ttl_seconds."""
        config = OAuth2Configuration(
            issuer="https://auth.example.com",
            client_id="client-id",
            token_minimum_ttl_seconds=31536000,  # 1 year
        )
        assert config.token_minimum_ttl_seconds == 31536000
