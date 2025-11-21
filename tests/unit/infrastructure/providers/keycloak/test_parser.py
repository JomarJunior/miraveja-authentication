"""Unit tests for KeycloakClaimsParser."""

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from miraveja_auth.domain import TokenInvalidException
from miraveja_auth.infrastructure.providers.keycloak import KeycloakClaims, KeycloakClaimsParser


class TestKeycloakClaimsParserParse:
    """Test parse method."""

    def test_parse_with_valid_payload(self):
        """Test parsing a valid JWT payload."""
        parser = KeycloakClaimsParser()

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": 1234571490,
            "iat": 1234567890,
            "realm_access": {"roles": ["admin", "user"]},
            "resource_access": {
                "client1": {"roles": ["role1", "role2"]},
            },
        }

        result = parser.parse(payload)

        assert isinstance(result, KeycloakClaims)
        assert result.sub == "user-123"
        assert result.iss == "https://auth.example.com"
        assert result.realm_access == {"roles": ["admin", "user"]}
        assert result.resource_access == {"client1": {"roles": ["role1", "role2"]}}

    def test_parse_with_minimal_payload(self):
        """Test parsing a minimal valid JWT payload."""
        parser = KeycloakClaimsParser()

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": 1234571490,
            "iat": 1234567890,
        }

        result = parser.parse(payload)

        assert isinstance(result, KeycloakClaims)
        assert result.sub == "user-123"
        assert result.realm_access is None
        assert result.resource_access is None

    def test_parse_with_extra_fields(self):
        """Test parsing payload with extra fields (allowed by BaseClaims)."""
        parser = KeycloakClaimsParser()

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": 1234571490,
            "iat": 1234567890,
            "custom_field": "custom_value",
            "another_field": 42,
        }

        result = parser.parse(payload)

        assert isinstance(result, KeycloakClaims)
        assert result.sub == "user-123"
        assert result.custom_field == "custom_value"
        assert result.another_field == 42

    def test_parse_raises_token_invalid_exception_on_missing_required_field(self):
        """Test that parser raises TokenInvalidException when required field is missing."""
        parser = KeycloakClaimsParser()

        payload = {
            "sub": "user-123",
            "iat": 1234567890,
            # Missing iss, aud, exp
        }

        with pytest.raises(TokenInvalidException):
            parser.parse(payload)

    def test_parse_raises_token_invalid_exception_on_invalid_type(self):
        """Test that parser raises TokenInvalidException when field has invalid type."""
        parser = KeycloakClaimsParser()

        payload = {
            "iss": "https://auth.example.com",
            "sub": "user-123",
            "aud": "test-client",
            "exp": "not-an-int",  # Should be int
            "iat": 1234567890,
        }

        with pytest.raises(TokenInvalidException):
            parser.parse(payload)

    def test_parse_raises_token_invalid_exception_on_pydantic_error(self):
        """Test that any Pydantic ValidationError is converted to TokenInvalidException."""
        parser = KeycloakClaimsParser()

        # Empty payload will fail validation
        payload = {}

        with pytest.raises(TokenInvalidException):
            parser.parse(payload)

    def test_parse_exception_chains_original_error(self):
        """Test that TokenInvalidException chains the original exception."""
        parser = KeycloakClaimsParser()

        payload = {"sub": "user-123"}  # Missing required fields

        with pytest.raises(TokenInvalidException) as exc_info:
            parser.parse(payload)

        # Check that the exception was chained
        assert exc_info.value.__cause__ is not None
