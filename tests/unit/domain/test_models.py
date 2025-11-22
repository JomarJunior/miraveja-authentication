"""Unit tests for domain models."""

from typing import Dict, List

import pytest
from pydantic import ValidationError

from miraveja_auth.domain.exceptions import AuthorizationException
from miraveja_auth.domain.models import BaseClaims, Role, Token, User


class TestRole:
    """Test suite for Role model."""

    def test_create_with_required_fields_only(self):
        """Test creating role with only required fields."""
        role = Role(name="admin")
        assert role.name == "admin"
        assert role.id is None
        assert role.description is None
        assert role.composite is False
        assert role.client_role is False
        assert role.container_id is None

    def test_create_with_all_fields(self):
        """Test creating role with all fields using aliases."""
        role = Role(
            id="role-123",
            name="editor",
            description="Editor role",
            composite=True,
            clientRole=True,
            containerId="container-456",
        )
        assert role.id == "role-123"
        assert role.name == "editor"
        assert role.description == "Editor role"
        assert role.composite is True
        assert role.client_role is True
        assert role.container_id == "container-456"

    def test_field_alias_client_role(self):
        """Test clientRole field alias."""
        # Using camelCase alias (proper way with Pydantic alias)
        role = Role(name="test", clientRole=True)
        assert role.client_role is True

        # Verify default is False when not provided
        role2 = Role(name="test")
        assert role2.client_role is False

    def test_field_alias_container_id(self):
        """Test containerId field alias."""
        # Using camelCase alias (proper way with Pydantic alias)
        role = Role(name="test", containerId="container-123")
        assert role.container_id == "container-123"

        # Verify default is None when not provided
        role2 = Role(name="test")
        assert role2.container_id is None

    def test_model_is_frozen(self):
        """Test that Role model is immutable (frozen)."""
        role = Role(name="admin")
        with pytest.raises(ValidationError) as exc_info:
            role.name = "superadmin"
        assert "frozen" in str(exc_info.value).lower()

    def test_default_values(self):
        """Test default values for optional fields."""
        role = Role(name="user")
        assert role.composite is False
        assert role.client_role is False
        assert role.id is None
        assert role.description is None
        assert role.container_id is None

    def test_missing_required_field(self):
        """Test that creating role without required name field fails."""
        with pytest.raises(ValidationError) as exc_info:
            Role()
        assert "name" in str(exc_info.value).lower()

    def test_equality_based_on_values(self):
        """Test that roles with same values are equal."""
        role1 = Role(name="admin", id="123")
        role2 = Role(name="admin", id="123")
        assert role1 == role2

    def test_inequality_based_on_values(self):
        """Test that roles with different values are not equal."""
        role1 = Role(name="admin")
        role2 = Role(name="user")
        assert role1 != role2


class TestBaseClaims:
    """Test suite for BaseClaims abstract base class."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that BaseClaims cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            BaseClaims(
                iss="https://auth.example.com",
                sub="user-123",
                aud="client-id",
                exp=1700000000,
                iat=1699996400,
            )
        assert "abstract" in str(exc_info.value).lower()

    def test_concrete_implementation_required_fields(self):
        """Test concrete implementation with required fields only."""

        class ConcreteClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        claims = ConcreteClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="client-id",
            exp=1700000000,
            iat=1699996400,
        )
        assert claims.iss == "https://auth.example.com"
        assert claims.sub == "user-123"
        assert claims.aud == ["client-id"]
        assert claims.exp == 1700000000
        assert claims.iat == 1699996400

    def test_concrete_implementation_with_optional_fields(self):
        """Test concrete implementation with optional fields."""

        class ConcreteClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        claims = ConcreteClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="client-id",
            exp=1700000000,
            iat=1699996400,
            jti="token-id",
            typ="Bearer",
            azp="authorized-party",
            scope="openid profile email",
            email="user@example.com",
            email_verified=True,
            preferred_username="john_doe",
        )
        assert claims.jti == "token-id"
        assert claims.typ == "Bearer"
        assert claims.azp == "authorized-party"
        assert claims.scope == "openid profile email"
        assert claims.email == "user@example.com"
        assert claims.email_verified is True
        assert claims.preferred_username == "john_doe"

    def test_concrete_implementation_extra_fields_allowed(self):
        """Test that extra fields are allowed in concrete implementations."""

        class ConcreteClaims(BaseClaims):
            custom_field: str = None

            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        claims = ConcreteClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="client-id",
            exp=1700000000,
            iat=1699996400,
            custom_field="custom_value",
            extra_field="extra_value",
        )
        assert claims.custom_field == "custom_value"
        # extra_field should be accessible via model_extra or __pydantic_extra__
        assert hasattr(claims, "__pydantic_extra__") or hasattr(claims, "model_extra")

    def test_model_is_frozen(self):
        """Test that BaseClaims concrete implementations are immutable."""

        class ConcreteClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        claims = ConcreteClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="client-id",
            exp=1700000000,
            iat=1699996400,
        )
        with pytest.raises(ValidationError) as exc_info:
            claims.sub = "user-456"
        assert "frozen" in str(exc_info.value).lower()

    def test_missing_required_fields(self):
        """Test that missing required fields raises validation error."""

        class ConcreteClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        # Missing iss
        with pytest.raises(ValidationError) as exc_info:
            ConcreteClaims(sub="user-123", aud="client-id", exp=1700000000, iat=1699996400)
        assert "iss" in str(exc_info.value).lower()

        # Missing sub
        with pytest.raises(ValidationError) as exc_info:
            ConcreteClaims(iss="issuer", aud="client-id", exp=1700000000, iat=1699996400)
        assert "sub" in str(exc_info.value).lower()

        # Missing aud
        with pytest.raises(ValidationError) as exc_info:
            ConcreteClaims(iss="issuer", sub="user-123", exp=1700000000, iat=1699996400)
        assert "aud" in str(exc_info.value).lower()

        # Missing exp
        with pytest.raises(ValidationError) as exc_info:
            ConcreteClaims(iss="issuer", sub="user-123", aud="client-id", iat=1699996400)
        assert "exp" in str(exc_info.value).lower()

        # Missing iat
        with pytest.raises(ValidationError) as exc_info:
            ConcreteClaims(iss="issuer", sub="user-123", aud="client-id", exp=1700000000)
        assert "iat" in str(exc_info.value).lower()

    def test_abstract_methods_must_be_implemented(self):
        """Test that abstract methods must be implemented in concrete classes."""

        # Missing get_roles - can define class but cannot instantiate
        class IncompleteClaims1(BaseClaims):
            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        with pytest.raises(TypeError) as exc_info:
            IncompleteClaims1(
                iss="https://auth.example.com",
                sub="user-123",
                aud="client-id",
                exp=1700000000,
                iat=1699996400,
            )
        assert "abstract" in str(exc_info.value).lower() or "get_roles" in str(exc_info.value)

        # Missing get_client_roles
        class IncompleteClaims2(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        with pytest.raises(TypeError) as exc_info:
            IncompleteClaims2(
                iss="https://auth.example.com",
                sub="user-123",
                aud="client-id",
                exp=1700000000,
                iat=1699996400,
            )
        assert "abstract" in str(exc_info.value).lower() or "get_client_roles" in str(exc_info.value)

        # Missing get_all_client_roles
        class IncompleteClaims3(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

        with pytest.raises(TypeError) as exc_info:
            IncompleteClaims3(
                iss="https://auth.example.com",
                sub="user-123",
                aud="client-id",
                exp=1700000000,
                iat=1699996400,
            )
        assert "abstract" in str(exc_info.value).lower() or "get_all_client_roles" in str(exc_info.value)


class TestToken:
    """Test suite for Token model."""

    def test_create_with_required_fields(self):
        """Test creating token with required fields."""
        token = Token(
            access_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            expires_in_seconds=3600,
            token_type="Bearer",
        )
        assert token.access_token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert token.expires_in_seconds == 3600
        assert token.token_type == "Bearer"
        assert token.refresh_token is None
        assert token.id_token is None

    def test_create_with_all_fields(self):
        """Test creating token with all fields including optional ones."""
        token = Token(
            access_token="access_token_value",
            refresh_token="refresh_token_value",
            id_token="id_token_value",
            expires_in_seconds=7200,
            token_type="Bearer",
        )
        assert token.access_token == "access_token_value"
        assert token.refresh_token == "refresh_token_value"
        assert token.id_token == "id_token_value"
        assert token.expires_in_seconds == 7200
        assert token.token_type == "Bearer"

    def test_field_aliases(self):
        """Test that field aliases work correctly."""
        # Using snake_case (standard Python naming)
        token = Token(
            access_token="token1",
            refresh_token="token2",
            id_token="token3",
            expires_in_seconds=3600,
            token_type="Bearer",
        )
        assert token.access_token == "token1"
        assert token.refresh_token == "token2"
        assert token.id_token == "token3"

    def test_model_is_frozen(self):
        """Test that Token model is immutable (frozen)."""
        token = Token(access_token="token", expires_in_seconds=3600, token_type="Bearer")
        with pytest.raises(ValidationError) as exc_info:
            token.access_token = "new_token"
        assert "frozen" in str(exc_info.value).lower()

    def test_missing_required_fields(self):
        """Test that missing required fields raises validation error."""
        # Missing access_token
        with pytest.raises(ValidationError) as exc_info:
            Token(expires_in_seconds=3600, token_type="Bearer")
        assert "access_token" in str(exc_info.value).lower()

        # Missing expires_in_seconds
        with pytest.raises(ValidationError) as exc_info:
            Token(access_token="token", token_type="Bearer")
        assert "expires_in_seconds" in str(exc_info.value).lower()

        # Missing token_type
        with pytest.raises(ValidationError) as exc_info:
            Token(access_token="token", expires_in_seconds=3600)
        assert "token_type" in str(exc_info.value).lower()

    def test_default_values_for_optional_fields(self):
        """Test default values for optional fields."""
        token = Token(access_token="token", expires_in_seconds=3600, token_type="Bearer")
        assert token.refresh_token is None
        assert token.id_token is None

    def test_expires_in_seconds_must_be_integer(self):
        """Test that expires_in_seconds must be an integer."""
        # Valid integer
        token = Token(access_token="token", expires_in_seconds=3600, token_type="Bearer")
        assert token.expires_in_seconds == 3600

        # String that can be converted to int should work with Pydantic's coercion
        token2 = Token(access_token="token", expires_in_seconds="3600", token_type="Bearer")
        assert token2.expires_in_seconds == 3600


class TestUser:
    """Test suite for User model."""

    def test_create_with_required_fields_only(self):
        """Test creating user with only required field (id)."""
        user = User(id="user-123")
        assert user.id == "user-123"
        assert user.username is None
        assert user.email is None
        assert user.email_verified is None
        assert user.realm_roles == []
        assert user.client_roles == {}

    def test_create_with_all_fields(self):
        """Test creating user with all fields."""
        user = User(
            id="user-123",
            username="john_doe",
            email="john@example.com",
            email_verified=True,
            realm_roles=["admin", "user"],
            client_roles={"app1": ["editor"], "app2": ["viewer"]},
        )
        assert user.id == "user-123"
        assert user.username == "john_doe"
        assert user.email == "john@example.com"
        assert user.email_verified is True
        assert user.realm_roles == ["admin", "user"]
        assert user.client_roles == {"app1": ["editor"], "app2": ["viewer"]}

    def test_model_is_frozen(self):
        """Test that User model is immutable (frozen)."""
        user = User(id="user-123")
        with pytest.raises(ValidationError) as exc_info:
            user.id = "user-456"
        assert "frozen" in str(exc_info.value).lower()

    def test_default_values(self):
        """Test default values for optional fields."""
        user = User(id="user-123")
        assert user.realm_roles == []
        assert user.client_roles == {}

    def test_from_claims_factory_method(self):
        """Test creating User from Claims using from_claims factory method."""

        class MockClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return ["admin", "user"]

            def get_client_roles(self, client_id: str) -> List[str]:
                if client_id == "app1":
                    return ["editor"]
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {"app1": ["editor"], "app2": ["viewer"]}

        claims = MockClaims(
            iss="https://auth.example.com",
            sub="user-123",
            aud="client-id",
            exp=1700000000,
            iat=1699996400,
            email="john@example.com",
            email_verified=True,
            preferred_username="john_doe",
        )

        user = User.from_claims(claims)

        assert user.id == "user-123"
        assert user.username == "john_doe"
        assert user.email == "john@example.com"
        assert user.email_verified is True
        assert user.realm_roles == ["admin", "user"]
        assert user.client_roles == {"app1": ["editor"], "app2": ["viewer"]}

    def test_from_claims_with_minimal_claims(self):
        """Test from_claims with minimal claims (no optional fields)."""

        class MinimalClaims(BaseClaims):
            def get_roles(self) -> List[str]:
                return []

            def get_client_roles(self, client_id: str) -> List[str]:
                return []

            def get_all_client_roles(self) -> Dict[str, List[str]]:
                return {}

        claims = MinimalClaims(
            iss="https://auth.example.com",
            sub="user-789",
            aud="client-id",
            exp=1700000000,
            iat=1699996400,
        )

        user = User.from_claims(claims)

        assert user.id == "user-789"
        assert user.username is None
        assert user.email is None
        assert user.email_verified is None
        assert user.realm_roles == []
        assert user.client_roles == {}

    def test_has_realm_role_returns_true_when_role_exists(self):
        """Test has_realm_role returns True when user has the role."""
        user = User(id="user-123", realm_roles=["admin", "user", "editor"])
        assert user.has_realm_role("admin") is True
        assert user.has_realm_role("user") is True
        assert user.has_realm_role("editor") is True

    def test_has_realm_role_returns_false_when_role_missing(self):
        """Test has_realm_role returns False when user lacks the role."""
        user = User(id="user-123", realm_roles=["user"])
        assert user.has_realm_role("admin") is False
        assert user.has_realm_role("editor") is False
        assert user.has_realm_role("superadmin") is False

    def test_has_realm_role_case_sensitive(self):
        """Test has_realm_role is case-sensitive."""
        user = User(id="user-123", realm_roles=["Admin"])
        assert user.has_realm_role("Admin") is True
        assert user.has_realm_role("admin") is False
        assert user.has_realm_role("ADMIN") is False

    def test_has_realm_role_with_empty_roles(self):
        """Test has_realm_role with empty realm_roles list."""
        user = User(id="user-123", realm_roles=[])
        assert user.has_realm_role("admin") is False

    def test_require_realm_role_succeeds_when_role_exists(self):
        """Test require_realm_role succeeds when user has the role."""
        user = User(id="user-123", realm_roles=["admin", "user"])
        # Should not raise exception
        user.require_realm_role("admin")
        user.require_realm_role("user")

    def test_require_realm_role_raises_when_role_missing(self):
        """Test require_realm_role raises AuthorizationException when role missing."""
        user = User(id="user-123", realm_roles=["user"])

        with pytest.raises(AuthorizationException) as exc_info:
            user.require_realm_role("admin")

        exception = exc_info.value
        assert exception.required_role == "admin"
        assert "admin" in exception.message

    def test_require_realm_role_with_empty_roles(self):
        """Test require_realm_role with empty realm_roles list."""
        user = User(id="user-123", realm_roles=[])

        with pytest.raises(AuthorizationException) as exc_info:
            user.require_realm_role("user")

        assert exc_info.value.required_role == "user"

    def test_has_client_role_returns_true_when_role_exists(self):
        """Test has_client_role returns True when user has the client role."""
        user = User(
            id="user-123",
            client_roles={
                "app1": ["editor", "viewer"],
                "app2": ["admin"],
            },
        )
        assert user.has_client_role("app1", "editor") is True
        assert user.has_client_role("app1", "viewer") is True
        assert user.has_client_role("app2", "admin") is True

    def test_has_client_role_returns_false_when_role_missing(self):
        """Test has_client_role returns False when user lacks the client role."""
        user = User(
            id="user-123",
            client_roles={"app1": ["viewer"]},
        )
        assert user.has_client_role("app1", "editor") is False
        assert user.has_client_role("app1", "admin") is False

    def test_has_client_role_returns_false_when_client_missing(self):
        """Test has_client_role returns False when client doesn't exist."""
        user = User(
            id="user-123",
            client_roles={"app1": ["editor"]},
        )
        assert user.has_client_role("app2", "editor") is False
        assert user.has_client_role("nonexistent", "admin") is False

    def test_has_client_role_case_sensitive(self):
        """Test has_client_role is case-sensitive."""
        user = User(
            id="user-123",
            client_roles={"App1": ["Editor"]},
        )
        assert user.has_client_role("App1", "Editor") is True
        assert user.has_client_role("app1", "Editor") is False
        assert user.has_client_role("App1", "editor") is False

    def test_has_client_role_with_empty_roles(self):
        """Test has_client_role with empty client_roles dict."""
        user = User(id="user-123", client_roles={})
        assert user.has_client_role("app1", "admin") is False

    def test_require_client_role_succeeds_when_role_exists(self):
        """Test require_client_role succeeds when user has the client role."""
        user = User(
            id="user-123",
            client_roles={
                "app1": ["editor", "viewer"],
                "app2": ["admin"],
            },
        )
        # Should not raise exception
        user.require_client_role("app1", "editor")
        user.require_client_role("app2", "admin")

    def test_require_client_role_raises_when_role_missing(self):
        """Test require_client_role raises AuthorizationException when role missing."""
        user = User(
            id="user-123",
            client_roles={"app1": ["viewer"]},
        )

        with pytest.raises(AuthorizationException) as exc_info:
            user.require_client_role("app1", "editor")

        exception = exc_info.value
        assert exception.required_role == "app1:editor"
        assert "app1:editor" in exception.message

    def test_require_client_role_raises_when_client_missing(self):
        """Test require_client_role raises AuthorizationException when client missing."""
        user = User(
            id="user-123",
            client_roles={"app1": ["editor"]},
        )

        with pytest.raises(AuthorizationException) as exc_info:
            user.require_client_role("app2", "admin")

        exception = exc_info.value
        assert exception.required_role == "app2:admin"

    def test_require_client_role_with_empty_roles(self):
        """Test require_client_role with empty client_roles dict."""
        user = User(id="user-123", client_roles={})

        with pytest.raises(AuthorizationException) as exc_info:
            user.require_client_role("app1", "admin")

        assert exc_info.value.required_role == "app1:admin"

    def test_multiple_roles_per_client(self):
        """Test user with multiple roles for a single client."""
        user = User(
            id="user-123",
            client_roles={"app1": ["admin", "editor", "viewer"]},
        )
        assert user.has_client_role("app1", "admin") is True
        assert user.has_client_role("app1", "editor") is True
        assert user.has_client_role("app1", "viewer") is True
        assert user.has_client_role("app1", "superadmin") is False

    def test_multiple_clients_with_roles(self):
        """Test user with roles across multiple clients."""
        user = User(
            id="user-123",
            client_roles={
                "app1": ["editor"],
                "app2": ["viewer"],
                "app3": ["admin"],
            },
        )
        assert user.has_client_role("app1", "editor") is True
        assert user.has_client_role("app2", "viewer") is True
        assert user.has_client_role("app3", "admin") is True
        # Cross-client roles should not exist
        assert user.has_client_role("app1", "viewer") is False
        assert user.has_client_role("app2", "admin") is False
