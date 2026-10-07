import json

from storage_conformance import StorageConformance

from oauth21_asgi import MemoryStorage
from oauth21_asgi.models import Client


class TestMemoryStorageConformance(StorageConformance):
    storage_factory = staticmethod(MemoryStorage)


def test_v1_snapshot_migration():
    storage = MemoryStorage()
    with storage.transaction() as unit:
        unit.put_client(
            Client(
                "old", ("https://client.test/cb",), "read", ("authorization_code",), issued_at=10
            )
        )
    snapshot = json.loads(json.dumps(storage.snapshot()))
    snapshot["schema"] = 1
    snapshot["clients"]["old"].pop("last_used_at")
    snapshot["clients"]["old"].pop("metadata_origin")
    restored = MemoryStorage.from_snapshot(snapshot)
    with restored.transaction() as unit:
        assert unit.get_client("old").last_used_at is None
        unit.prune(15, 10)
        assert unit.get_client("old")
        unit.prune(20, 10)
        assert unit.get_client("old") is None
    assert restored.snapshot()["schema"] == 2
