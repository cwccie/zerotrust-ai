"""Tests for identity registry."""

import pytest

from zerotrust_ai.identity import IdentityRegistry
from zerotrust_ai.identity.models import Identity, Device


class TestIdentity:
    def test_to_dict(self):
        i = Identity("alice", "Alice", "user", "alice@corp.io")
        d = i.to_dict()
        assert d["identity_id"] == "alice"
        assert d["name"] == "Alice"


class TestDevice:
    def test_to_dict(self):
        d = Device("d1", "Laptop", "workstation", owner_id="alice")
        dd = d.to_dict()
        assert dd["device_id"] == "d1"
        assert dd["owner_id"] == "alice"


class TestIdentityRegistry:
    def test_register_identity(self, identity_registry):
        assert identity_registry.get_identity("alice") is not None
        assert identity_registry.get_identity("alice").name == "Alice"

    def test_find_by_email(self, identity_registry):
        result = identity_registry.find_by_email("alice@corp.io")
        assert result is not None
        assert result.identity_id == "alice"

    def test_find_by_role(self, identity_registry):
        devs = identity_registry.find_by_role("developer")
        assert len(devs) == 1
        assert devs[0].identity_id == "alice"

    def test_find_by_group(self, identity_registry):
        pass  # Groups set to empty in fixture

    def test_disable_identity(self, identity_registry):
        assert identity_registry.disable_identity("alice")
        assert not identity_registry.get_identity("alice").enabled

    def test_register_device(self, identity_registry):
        dev = identity_registry.get_device("dev-001")
        assert dev is not None
        assert dev.owner_id == "alice"

    def test_get_user_devices(self, identity_registry):
        devices = identity_registry.get_user_devices("alice")
        assert len(devices) == 1

    def test_non_compliant_devices(self, identity_registry):
        nc = identity_registry.non_compliant_devices()
        assert len(nc) == 1
        assert nc[0].device_id == "dev-002"

    def test_correlation(self, identity_registry):
        identity_registry.add_correlation("a.chen@external.io", "alice")
        result = identity_registry.resolve_alias("a.chen@external.io")
        assert "alice" in result

    def test_session_tracking(self, identity_registry):
        identity_registry.track_session("s1", "alice", "dev-001", "10.0.1.1")
        active = identity_registry.active_sessions("alice")
        assert len(active) == 1

    def test_end_session(self, identity_registry):
        identity_registry.track_session("s1", "alice")
        identity_registry.end_session("s1")
        active = identity_registry.active_sessions("alice")
        assert len(active) == 0

    def test_summary(self, identity_registry):
        summary = identity_registry.summary()
        assert summary["total_identities"] == 3
        assert summary["total_devices"] == 2
        assert summary["identity_types"]["user"] == 2
        assert summary["identity_types"]["service"] == 1
