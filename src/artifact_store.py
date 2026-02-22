"""Thread-safe key-value store for cross-phase artifact sharing.

Enables exploit sub-phases running in parallel to share artefacts such as
JWT tokens, extracted credentials, and enumerated data.  A single instance
is created by the pipeline and injected into every agent's tool dispatcher
so that, for example, the **auth** agent can store an admin JWT and the
**authz** or **XSS** agent can retrieve it without re-authenticating.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger("spaider.artifact_store")


class ArtifactStore:
    """Thread-safe key-value store for cross-phase artifact sharing."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._lock = threading.Lock()

    # -- mutators --------------------------------------------------------- #

    def put(self, key: str, value: Any) -> None:
        """Store an artifact under *key*, overwriting any previous value."""
        with self._lock:
            self._data[key] = value
            logger.info("ArtifactStore: stored '%s' (%d chars)", key, len(str(value)))

    def delete(self, key: str) -> bool:
        """Remove an artifact.  Returns ``True`` if the key existed."""
        with self._lock:
            existed = key in self._data
            self._data.pop(key, None)
            return existed

    # -- accessors -------------------------------------------------------- #

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve an artifact by *key*, or *default* if not found."""
        with self._lock:
            return self._data.get(key, default)

    def keys(self) -> list[str]:
        """Return all stored artifact keys."""
        with self._lock:
            return list(self._data.keys())

    def get_all(self) -> dict[str, Any]:
        """Return a shallow copy of all stored artifacts."""
        with self._lock:
            return dict(self._data)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def __repr__(self) -> str:
        with self._lock:
            return f"ArtifactStore({list(self._data.keys())})"
