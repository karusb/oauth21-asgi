from __future__ import annotations

import copy
import hashlib
import secrets
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict
from threading import RLock
from typing import Any

from .models import Client, Code, Grant, PendingConsent, Subject, TokenKind


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class MemoryUnitOfWork:
    def __init__(self, data: dict[str, dict[str, Any]]) -> None:
        self.data = data

    def get_client(self, client_id: str) -> Client | None:
        return self.data["clients"].get(client_id)

    def put_client(self, client: Client) -> None:
        self.data["clients"][client.client_id] = client

    def clients(self) -> list[Client]:
        return list(self.data["clients"].values())

    def delete_client(self, client_id: str) -> None:
        self.data["clients"].pop(client_id, None)
        for group in ("codes", "grants"):
            self.data[group] = {
                k: v for k, v in self.data[group].items() if v.client_id != client_id
            }
        self.data["pending"] = {
            k: v for k, v in self.data["pending"].items() if v.parameters["client_id"] != client_id
        }

    def get_code(self, fingerprint: str) -> Code | None:
        return self.data["codes"].get(fingerprint)

    def put_code(self, code: Code) -> None:
        self.data["codes"][code.digest] = code

    def delete_code(self, fingerprint: str) -> None:
        self.data["codes"].pop(fingerprint, None)

    def codes(self) -> list[Code]:
        return list(self.data["codes"].values())

    def get_pending(self, fingerprint: str) -> PendingConsent | None:
        return self.data["pending"].get(fingerprint)

    def put_pending(self, pending: PendingConsent) -> None:
        self.data["pending"][pending.digest] = pending

    def delete_pending(self, fingerprint: str) -> None:
        self.data["pending"].pop(fingerprint, None)

    def pending(self) -> list[PendingConsent]:
        return list(self.data["pending"].values())

    def get_grant(self, family_id: str) -> Grant | None:
        return self.data["grants"].get(family_id)

    def put_grant(self, grant: Grant) -> None:
        self.data["grants"][grant.family_id] = grant

    def grants(self) -> list[Grant]:
        return list(self.data["grants"].values())

    def find_token(self, fingerprint: str, kind: TokenKind) -> Grant | None:
        if kind not in ("access_token", "refresh_token"):
            raise ValueError("Unknown token kind")
        for grant in self.grants():
            candidates = (
                (grant.access_digest,)
                if kind == "access_token"
                else (grant.refresh_digest or "", *grant.used_refresh)
            )
            if any(secrets.compare_digest(fingerprint, v) for v in candidates):
                return grant
        return None

    def prune(self, now: float, client_ttl: int) -> None:
        for group in ("codes", "pending", "grants"):
            self.data[group] = {k: v for k, v in self.data[group].items() if v.expires_at > now}
        protected = {code.client_id for code in self.codes()}
        protected.update(g.client_id for g in self.grants() if not g.revoked)
        protected.update(p.parameters["client_id"] for p in self.pending())
        for client in self.clients():
            last_used = client.last_used_at if client.last_used_at is not None else client.issued_at
            if client.client_id not in protected and last_used + client_ttl <= now:
                self.delete_client(client.client_id)


class MemoryStorage:
    """Development/single-process only. NOT durable or cross-worker storage."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._data: dict[str, dict[str, Any]] = {
            "clients": {},
            "codes": {},
            "pending": {},
            "grants": {},
        }

    @contextmanager
    def transaction(self) -> Iterator[MemoryUnitOfWork]:
        with self._lock:
            working = copy.deepcopy(self._data)
            yield MemoryUnitOfWork(working)
            self._data = working

    def snapshot(self) -> dict[str, Any]:
        """Trusted development fixture export, never bearer credentials."""
        with self._lock:
            return {
                "schema": 2,
                **{
                    g: {k: asdict(v) for k, v in records.items()}
                    for g, records in self._data.items()
                },
            }

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any]) -> MemoryStorage:
        """Load trusted fixtures; not a production persistence adapter."""
        if snapshot.get("schema") not in (1, 2):
            raise ValueError("Unsupported snapshot schema")
        result = cls()
        constructors = {
            "clients": Client,
            "codes": Code,
            "pending": PendingConsent,
            "grants": Grant,
        }
        for group, constructor in constructors.items():
            for key, fields in snapshot[group].items():
                value = dict(fields)
                if "subject" in value:
                    value["subject"] = Subject(**value["subject"])
                for name in ("redirect_uris", "grant_types", "response_types", "used_refresh"):
                    if name in value:
                        value[name] = tuple(value[name])
                result._data[group][key] = constructor(**value)
        return result
