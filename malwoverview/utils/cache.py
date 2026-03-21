import sqlite3
import json
import time
import os
import functools
from pathlib import Path

import malwoverview.modules.configvars as cv


class ResultCache:
    def __init__(self, db_path=None, default_ttl=3600):
        if db_path is None:
            db_path = os.path.join(str(Path.home()), '.malwoverview_cache.db')
        self.db_path = db_path
        self.default_ttl = default_ttl
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            'CREATE TABLE IF NOT EXISTS cache '
            '(key TEXT PRIMARY KEY, value TEXT, timestamp REAL)'
        )
        self.conn.commit()

    def get(self, key):
        cursor = self.conn.execute(
            'SELECT value, timestamp FROM cache WHERE key=?', (key,)
        )
        row = cursor.fetchone()
        if row is not None:
            value, timestamp = row
            if time.time() - timestamp < self.default_ttl:
                return json.loads(value)
        return None

    def put(self, key, value, ttl=None):
        self.conn.execute(
            'INSERT OR REPLACE INTO cache (key, value, timestamp) VALUES (?, ?, ?)',
            (key, json.dumps(value), time.time())
        )
        self.conn.commit()

    def clear(self):
        self.conn.execute('DELETE FROM cache')
        self.conn.commit()

    def prune(self):
        self.conn.execute(
            'DELETE FROM cache WHERE timestamp < ?',
            (time.time() - self.default_ttl,)
        )
        self.conn.commit()

    def close(self):
        self.conn.close()


def cached(key_prefix):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not cv.cache_enabled:
                return func(*args, **kwargs)
            cache = ResultCache(default_ttl=cv.cache_ttl)
            cache_key = key_prefix + ":" + ":".join(str(a) for a in args[1:])
            result = cache.get(cache_key)
            if result is not None:
                return result
            result = func(*args, **kwargs)
            if result is not None:
                cache.put(cache_key, result)
            cache.close()
            return result
        return wrapper
    return decorator
