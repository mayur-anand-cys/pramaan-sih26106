"""
Cache layer for the PRAMAAN Threat Intel Aggregator.

Primary: Redis (30-day TTL)
Fallback: In-memory LRU dict (auto-used if Redis unreachable)
"""
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

try:
    import redis  # type: ignore
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days
KEY_PREFIX = "pramaan:intel:"


class InMemoryCache:
    """Simple dict-based cache with TTL. Used as fallback when Redis is down."""

    def __init__(self, max_size: int = 10000):
        self._store: Dict[str, Tuple[float, str]] = {}
        self.max_size = max_size

    def get(self, key: str) -> Optional[str]:
        item = self._store.get(key)
        if not item:
            return None
        expiry, value = item
        if expiry < time.time():
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: str, ttl: int = DEFAULT_TTL_SECONDS) -> None:
        if len(self._store) >= self.max_size:
            # Simple eviction: drop oldest 10%
            keys = sorted(self._store, key=lambda k: self._store[k][0])
            for k in keys[: self.max_size // 10]:
                self._store.pop(k, None)
        self._store[key] = (time.time() + ttl, value)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def size(self) -> int:
        return len(self._store)


class IntelCache:
    """
    Unified cache abstraction. Tries Redis first; falls back to in-memory.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        self.memory = InMemoryCache()
        self.using_redis = False
        self._stats = {"hits": 0, "misses": 0, "sets": 0}

        redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")

        if HAS_REDIS:
            try:
                self.redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                # ping to verify
                self.redis_client.ping()
                self.using_redis = True
            except Exception:
                self.redis_client = None
                self.using_redis = False

    def _key(self, indicator: str, provider: str) -> str:
        return f"{KEY_PREFIX}{provider}:{indicator}"

    def get(self, indicator: str, provider: str) -> Optional[Dict[str, Any]]:
        key = self._key(indicator, provider)

        if self.using_redis and self.redis_client:
            try:
                raw = self.redis_client.get(key)
                if raw:
                    self._stats["hits"] += 1
                    return json.loads(raw)
                self._stats["misses"] += 1
                return None
            except Exception:
                # Redis failed mid-request, fall through to memory
                pass

        raw = self.memory.get(key)
        if raw:
            self._stats["hits"] += 1
            return json.loads(raw)
        self._stats["misses"] += 1
        return None

    def set(
        self,
        indicator: str,
        provider: str,
        data: Dict[str, Any],
        ttl: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        key = self._key(indicator, provider)
        payload = json.dumps(data, default=str)

        if self.using_redis and self.redis_client:
            try:
                self.redis_client.setex(key, ttl, payload)
                self._stats["sets"] += 1
                return
            except Exception:
                pass

        self.memory.set(key, payload, ttl)
        self._stats["sets"] += 1

    def delete(self, indicator: str, provider: str) -> None:
        key = self._key(indicator, provider)
        if self.using_redis and self.redis_client:
            try:
                self.redis_client.delete(key)
            except Exception:
                pass
        self.memory.delete(key)

    def clear_all(self) -> None:
        if self.using_redis and self.redis_client:
            try:
                keys = self.redis_client.keys(f"{KEY_PREFIX}*")
                if keys:
                    self.redis_client.delete(*keys)
            except Exception:
                pass
        self.memory.clear()

    def get_stats(self) -> Dict[str, Any]:
        total = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total) if total > 0 else 0.0
        return {
            "backend": "redis" if self.using_redis else "memory",
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "sets": self._stats["sets"],
            "hit_rate": round(hit_rate, 4),
            "memory_size": self.memory.size(),
        }


# ── Singleton ──
_cache_instance: Optional[IntelCache] = None


def get_cache() -> IntelCache:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = IntelCache()
    return _cache_instance


def reset_cache_for_tests() -> None:
    """Only used in test suite."""
    global _cache_instance
    if _cache_instance is not None:
        _cache_instance.clear_all()
    _cache_instance = None
