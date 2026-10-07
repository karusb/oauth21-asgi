"""Reusable adapter tests. Subclass StorageConformance and supply storage_factory.

The factory must return a fresh empty Storage for each test. Run this against the
real transactional backend, not a mock. Multi-process durability remains the host's
responsibility; the suite covers observable public contracts in one test process.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from conftest import A, System

from oauth21_asgi import Limits
from oauth21_asgi.models import Client
from oauth21_asgi.storage import digest


class StorageConformance:
    storage_factory = None

    def system(self, **kwargs):
        return System(storage=self.storage_factory(), **kwargs)

    def test_rollback(self):
        storage = self.storage_factory()
        client = Client("id", ("https://client.test/cb",), "read", ("authorization_code",))
        with pytest.raises(RuntimeError), storage.transaction() as unit:
            unit.put_client(client)
            raise RuntimeError("injected transaction failure")
        with storage.transaction() as unit:
            assert unit.get_client("id") is None

    def test_atomic_code_consumption(self):
        system = self.system()
        cid = system.client()
        code = system.code(cid)
        gate = Barrier(2)

        def exchange():
            gate.wait(timeout=10)
            return system.exchange(cid, code).status_code

        with ThreadPoolExecutor(2) as pool:
            jobs = [pool.submit(exchange) for _ in range(2)]
            assert sorted(job.result() for job in jobs) == [200, 400]
        with system.storage.transaction() as unit:
            assert unit.get_code(digest(code)) is None
            assert len(unit.grants()) == 1

    def test_concurrent_refresh_replay(self):
        system = self.system()
        cid, token = system.tokens()
        gate = Barrier(2)

        def refresh():
            gate.wait(timeout=10)
            return system.refresh(cid, token["refresh_token"])

        with ThreadPoolExecutor(2) as pool:
            jobs = [pool.submit(refresh) for _ in range(2)]
            results = [job.result() for job in jobs]
        assert sorted(reply.status_code for reply in results) == [200, 400]
        successor = next(reply.json() for reply in results if reply.status_code == 200)
        assert system.oauth.validate_access_token(successor["access_token"], resource=A) is None

    def test_active_clients_and_inactive_pruning(self):
        system = self.system(
            limits=replace(Limits(), client_ttl=10, grant_ttl=1000, access_ttl=1000)
        )
        active, token = system.tokens()
        inactive = system.client()
        for _ in range(4):
            system.now += 9
            assert system.oauth.validate_access_token(token["access_token"], resource=A)
            system.oauth.prune()
        with system.storage.transaction() as unit:
            assert unit.get_client(active).last_used_at == system.now
            assert unit.get_client(inactive) is None
        # Even when a client has not been touched recently, a live grant protects it.
        system.now += 50
        system.oauth.prune()
        with system.storage.transaction() as unit:
            assert unit.get_client(active) is not None
        system.oauth.revoke_subject("alice")
        system.now += 11
        system.oauth.prune()
        with system.storage.transaction() as unit:
            assert unit.get_client(active) is None

    def test_codes_and_pending_protect_inactive_clients(self):
        system = self.system(limits=replace(Limits(), client_ttl=10))
        code_client = system.client()
        system.code(code_client)
        pending_client = system.client()
        system.http.get(system.oauth.paths.authorize, params=system.parameters(pending_client))
        system.now += 11
        system.oauth.prune()
        with system.storage.transaction() as unit:
            assert unit.get_client(code_client)
            assert unit.get_client(pending_client)

    def test_subject_invalidation_and_digest_secrecy(self):
        system = self.system()
        cid, token = system.tokens()
        code = system.code(cid)
        with system.storage.transaction() as unit:
            representation = json.dumps([vars(value) for value in unit.grants()], default=str)
            assert code not in representation
            assert token["access_token"] not in representation
            assert token["refresh_token"] not in representation
            assert unit.find_token(digest(token["access_token"]), "access_token")
            assert unit.find_token(digest(token["refresh_token"]), "refresh_token")
        system.identity.subject = replace(system.identity.subject, authorization_version="new")
        assert system.exchange(cid, code).status_code == 400
        assert system.oauth.validate_access_token(token["access_token"], resource=A) is None
        assert system.refresh(cid, token["refresh_token"]).status_code == 400

    def test_invalid_token_kind_rejected(self):
        with self.storage_factory().transaction() as unit, pytest.raises(ValueError):
            unit.find_token("digest", "arbitrary")
