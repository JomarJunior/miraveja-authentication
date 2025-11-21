"""Unit tests for KeycloakClaims."""

import pytest
from pydantic import ValidationError

from miraveja_auth.infrastructure.providers.keycloak import KeycloakClaims


class TestKeycloakClaimsInitialization:
    """Test KeycloakClaims initialization."""

    def test_init_with_minimal_fields(self):
        """Test initialization with only required fields."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
        )

        assert claims.sub == "user-123"
        assert claims.iat == 1234567890
        assert claims.realm_access is None
        assert claims.resource_access is None

    def test_init_with_all_fields(self):
        """Test initialization with all fields."""
        claims = KeycloakClaims(
            sub="user-123",
            iat=1234567890,
            exp=1234571490,
            iss="https://auth.example.com",
            aud="test-client",
            realm_access={"roles": ["admin", "user"]},
            resource_access={
                "client1": {"roles": ["role1", "role2"]},
                "client2": {"roles": ["role3"]},
            },
        )

        assert claims.sub == "user-123"
        assert claims.realm_access == {"roles": ["admin", "user"]}
        assert claims.resource_access == {
            "client1": {"roles": ["role1", "role2"]},
            "client2": {"roles": ["role3"]},
        }

    def test_init_with_empty_realm_access(self):
        """Test initialization with empty realm_access."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            realm_access={},
        )

        assert claims.realm_access == {}

    def test_init_with_empty_resource_access(self):
        """Test initialization with empty resource_access."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={},
        )

        assert claims.resource_access == {}

    def test_init_allows_extra_fields(self):
        """Test that extra fields are allowed (BaseClaims behavior)."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            custom_field="custom_value",
            another_field=42,
        )

        assert claims.sub == "user-123"
        assert claims.custom_field == "custom_value"
        assert claims.another_field == 42


class TestKeycloakClaimsGetRoles:
    """Test get_roles method."""

    def test_get_roles_returns_realm_roles(self):
        """Test get_roles returns realm roles from realm_access."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            realm_access={"roles": ["admin", "user", "viewer"]},
        )

        roles = claims.get_roles()

        assert roles == ["admin", "user", "viewer"]

    def test_get_roles_returns_empty_list_when_realm_access_none(self):
        """Test get_roles returns empty list when realm_access is None."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
        )

        roles = claims.get_roles()

        assert roles == []

    def test_get_roles_returns_empty_list_when_realm_access_empty(self):
        """Test get_roles returns empty list when realm_access is empty dict."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            realm_access={},
        )

        roles = claims.get_roles()

        assert roles == []

    def test_get_roles_returns_empty_list_when_roles_key_missing(self):
        """Test get_roles returns empty list when 'roles' key is missing."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            realm_access={"roles": []},
        )

        roles = claims.get_roles()

        assert roles == []

    def test_get_roles_returns_empty_list_when_roles_empty(self):
        """Test get_roles returns empty list when roles list is empty."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            realm_access={"roles": []},
        )

        roles = claims.get_roles()

        assert roles == []

    def test_get_roles_with_single_role(self):
        """Test get_roles with single realm role."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            realm_access={"roles": ["admin"]},
        )

        roles = claims.get_roles()

        assert roles == ["admin"]


class TestKeycloakClaimsGetAllClientRoles:
    """Test get_all_client_roles method."""

    def test_get_all_client_roles_returns_all_clients(self):
        """Test get_all_client_roles returns roles for all clients."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1", "role2"]},
                "client2": {"roles": ["role3"]},
                "client3": {"roles": ["role4", "role5", "role6"]},
            },
        )

        all_roles = claims.get_all_client_roles()

        assert all_roles == {
            "client1": ["role1", "role2"],
            "client2": ["role3"],
            "client3": ["role4", "role5", "role6"],
        }

    def test_get_all_client_roles_returns_empty_dict_when_resource_access_none(self):
        """Test get_all_client_roles returns empty dict when resource_access is None."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
        )

        all_roles = claims.get_all_client_roles()

        assert all_roles == {}

    def test_get_all_client_roles_returns_empty_dict_when_resource_access_empty(self):
        """Test get_all_client_roles returns empty dict when resource_access is empty."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={},
        )

        all_roles = claims.get_all_client_roles()

        assert all_roles == {}

    def test_get_all_client_roles_excludes_clients_without_roles_key(self):
        """Test get_all_client_roles excludes clients without 'roles' key."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1"]},
                "client2": {"roles": []},
            },
        )

        all_roles = claims.get_all_client_roles()

        assert all_roles == {"client1": ["role1"]}

    def test_get_all_client_roles_excludes_clients_with_empty_roles(self):
        """Test get_all_client_roles excludes clients with empty roles list."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1"]},
                "client2": {"roles": []},
            },
        )

        all_roles = claims.get_all_client_roles()

        assert all_roles == {"client1": ["role1"]}

    def test_get_all_client_roles_with_single_client(self):
        """Test get_all_client_roles with single client."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1", "role2"]},
            },
        )

        all_roles = claims.get_all_client_roles()

        assert all_roles == {"client1": ["role1", "role2"]}


class TestKeycloakClaimsGetClientRoles:
    """Test get_client_roles method."""

    def test_get_client_roles_returns_roles_for_client(self):
        """Test get_client_roles returns roles for specified client."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1", "role2"]},
                "client2": {"roles": ["role3"]},
            },
        )

        roles = claims.get_client_roles("client1")

        assert roles == ["role1", "role2"]

    def test_get_client_roles_returns_empty_list_when_resource_access_none(self):
        """Test get_client_roles returns empty list when resource_access is None."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
        )

        roles = claims.get_client_roles("client1")

        assert roles == []

    def test_get_client_roles_returns_empty_list_when_client_not_found(self):
        """Test get_client_roles returns empty list when client ID not found."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1"]},
            },
        )

        roles = claims.get_client_roles("nonexistent-client")

        assert roles == []

    def test_get_client_roles_returns_empty_list_when_roles_key_missing(self):
        """Test get_client_roles returns empty list when 'roles' key is missing."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": []},
            },
        )

        roles = claims.get_client_roles("client1")

        assert roles == []

    def test_get_client_roles_returns_empty_list_when_roles_empty(self):
        """Test get_client_roles returns empty list when roles list is empty."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": []},
            },
        )

        roles = claims.get_client_roles("client1")

        assert roles == []

    def test_get_client_roles_with_single_role(self):
        """Test get_client_roles with single role for client."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["admin"]},
            },
        )

        roles = claims.get_client_roles("client1")

        assert roles == ["admin"]

    def test_get_client_roles_different_clients_have_different_roles(self):
        """Test that different clients have different roles."""
        claims = KeycloakClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="test-client",
            exp=1234571490,
            iat=1234567890,
            resource_access={
                "client1": {"roles": ["role1", "role2"]},
                "client2": {"roles": ["role3", "role4"]},
            },
        )

        roles_client1 = claims.get_client_roles("client1")
        roles_client2 = claims.get_client_roles("client2")

        assert roles_client1 == ["role1", "role2"]
        assert roles_client2 == ["role3", "role4"]
        assert roles_client1 != roles_client2
