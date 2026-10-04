"""SQLite 持久层：主体密钥、能力链及完整性报告。"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Callable, Iterator

from .config import settings
from .models import (
    CapabilityToken,
    ChainSubmission,
    IntegrityReport,
    RedemptionEvent,
    RevocationEvent,
)

SCHEMA = """
-- 签发主体：current_version 指向当前生效密钥；轮换只推进版本指针。
CREATE TABLE IF NOT EXISTS principals (
    name            TEXT PRIMARY KEY,
    current_version INTEGER NOT NULL CHECK (current_version >= 1),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- 主体密钥历史（只追加）：轮换写入新版本，旧版本永久保留，
-- 轮换前提交的链继续按钉扎的旧版本重验。任何接口都不回读该列给客户端。
CREATE TABLE IF NOT EXISTS principal_keys (
    name        TEXT NOT NULL,
    version     INTEGER NOT NULL CHECK (version >= 1),
    hmac_secret TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (name, version),
    FOREIGN KEY (name) REFERENCES principals (name)
);

CREATE TABLE IF NOT EXISTS chains (
    chain_id       TEXT PRIMARY KEY,
    content_sha256 TEXT NOT NULL,
    report_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

-- 链在提交事务所内钉扎的“签发者 -> 密钥版本”快照：
-- 后续查询 / 只读求值 / 核销始终按此版本取密钥，与主体当前版本无关。
CREATE TABLE IF NOT EXISTS chain_key_bindings (
    chain_id    TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    bound_at    TEXT NOT NULL,
    PRIMARY KEY (chain_id, issuer),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

CREATE TABLE IF NOT EXISTS tokens (
    chain_id    TEXT NOT NULL,
    position    INTEGER NOT NULL,
    token_json  TEXT NOT NULL,
    PRIMARY KEY (chain_id, position),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 撤销事件为只追加（append-only）审计记录：无更新 / 删除路径。
-- request_key 全局唯一（跨链也不可复用）；同一令牌至多一条有效撤销事件。
CREATE TABLE IF NOT EXISTS revocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    effective_at   TEXT NOT NULL,
    reason         TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);

-- 一次性访问核销：只在“末端 + 判定允许”时追加，成功后令牌不可再次核销。
-- request_key 全局唯一（重放/冲突判定）；同一链内同一令牌至多成功核销一次。
CREATE TABLE IF NOT EXISTS redemptions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id       TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    request_key    TEXT NOT NULL UNIQUE,
    request_path   TEXT NOT NULL,
    method         TEXT NOT NULL,
    source_ip      TEXT,
    request_body   TEXT,
    content_sha256 TEXT NOT NULL,
    evaluated_at   TEXT NOT NULL,
    redeemed_at    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    UNIQUE (chain_id, token_id),
    FOREIGN KEY (chain_id) REFERENCES chains (chain_id)
);
"""

DEMO_PRINCIPALS = {
    "root": settings.root_hmac_secret,
    "service-a": "demo-secret-service-a",
    "service-b": "demo-secret-service-b",
    "alice": "demo-secret-alice",
}


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # 并发写事务（BEGIN IMMEDIATE）锁竞争时等待而非立刻 SQLITE_BUSY
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI 依赖：每请求一个连接，自动提交 / 回滚。"""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    _migrate_legacy_principals(conn)
    conn.executescript(SCHEMA)
    if settings.seed_demo_principals:
        now = _now_iso()
        # 已存在（含迁移而来）的演示主体不覆盖其版本指针
        conn.executemany(
            "INSERT OR IGNORE INTO principals "
            "(name, current_version, created_at, updated_at) VALUES (?, 1, ?, ?)",
            [(name, now, now) for name in DEMO_PRINCIPALS],
        )
        # 主体缺失 v1 时补插演示密钥；已轮换过的主体保留其历史密钥
        conn.executemany(
            "INSERT OR IGNORE INTO principal_keys (name, version, hmac_secret, created_at) "
            "VALUES (?, 1, ?, ?)",
            [(name, secret, now) for name, secret in DEMO_PRINCIPALS.items()],
        )
    conn.commit()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        r["name"]
        for r in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _migrate_legacy_principals(conn: sqlite3.Connection) -> None:
    """把旧版单列密钥 principals(name,hmac_secret) 迁移到版本化结构。

    迁移与后续建表在同一事务中：任一步失败整体回滚，不存在部分切换。
    迁移后还为既有链回填 v1 绑定，使其永远按轮换前密钥重验。
    """
    tables = {
        r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if "principals" not in tables:
        return
    columns = _table_columns(conn, "principals")
    if "current_version" in columns:
        return  # 已是版本化结构

    now = _now_iso()
    conn.execute("ALTER TABLE principals RENAME TO principals_legacy")
    conn.executescript(SCHEMA)
    legacy = conn.execute(
        "SELECT name, hmac_secret FROM principals_legacy"
    ).fetchall()
    for row in legacy:
        conn.execute(
            "INSERT INTO principals (name, current_version, created_at, updated_at) "
            "VALUES (?, 1, ?, ?)",
            (row["name"], now, now),
        )
        conn.execute(
            "INSERT INTO principal_keys (name, version, hmac_secret, created_at) "
            "VALUES (?, 1, ?, ?)",
            (row["name"], row["hmac_secret"], now),
        )
    # 旧链提交时存在的签发者一律钉扎在 v1（只回填已注册签发者，
    # 与提交时 unknown_issuer 的既有结论保持一致）。
    conn.execute(
        "INSERT OR IGNORE INTO chain_key_bindings (chain_id, issuer, key_version, bound_at) "
        "SELECT DISTINCT t.chain_id, json_extract(t.token_json, '$.issuer'), 1, ? "
        "FROM tokens t "
        "JOIN principals p ON p.name = json_extract(t.token_json, '$.issuer')",
        (now,),
    )
    conn.execute("DROP TABLE principals_legacy")
    conn.commit()


def get_secret(conn: sqlite3.Connection, name: str) -> str | None:
    """取主体**当前**版本密钥（仅供注册 / 轮换管理用途）。

    已存链的重验不得使用本函数——应通过
    :class:`SubmissionSecretResolver`（提交时）或
    :func:`bound_secret_lookup`（已存链）按钉扎版本取密钥。
    """
    row = conn.execute(
        "SELECT k.hmac_secret AS hmac_secret FROM principals p "
        "JOIN principal_keys k ON k.name = p.name AND k.version = p.current_version "
        "WHERE p.name = ?",
        (name,),
    ).fetchone()
    return row["hmac_secret"] if row else None


def principal_current_version(conn: sqlite3.Connection, name: str) -> int | None:
    row = conn.execute(
        "SELECT current_version FROM principals WHERE name = ?", (name,)
    ).fetchone()
    return row["current_version"] if row else None


def upsert_principal(conn: sqlite3.Connection, name: str, secret: str) -> bool:
    """注册主体及其 v1 密钥（同一事务内两行）；已存在返回 False。"""
    now = _now_iso()
    cur = conn.execute(
        "INSERT INTO principals (name, current_version, created_at, updated_at) "
        "VALUES (?, 1, ?, ?)",
        (name, now, now),
    )
    conn.execute(
        "INSERT INTO principal_keys (name, version, hmac_secret, created_at) "
        "VALUES (?, 1, ?, ?)",
        (name, secret, now),
    )
    return cur.rowcount == 1


def rotate_principal_secret(
    conn: sqlite3.Connection, name: str, new_secret: str
) -> int:
    """在同一事务内为主体追加一个新版本密钥并推进当前版本指针。

    返回新版本号。主体不存在抛 :class:`LookupError`；
    新密钥与当前密钥完全相同抛 :class:`ValueError`（调用方映射为 409）。
    """
    row = conn.execute(
        "SELECT current_version FROM principals WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        raise LookupError(name)
    current_version = row["current_version"]
    current_secret = conn.execute(
        "SELECT hmac_secret FROM principal_keys WHERE name = ? AND version = ?",
        (name, current_version),
    ).fetchone()["hmac_secret"]
    if hmac_compare_strings(current_secret, new_secret):
        raise ValueError("新密钥不得与当前密钥相同")
    next_version = current_version + 1
    now = _now_iso()
    conn.execute(
        "INSERT INTO principal_keys (name, version, hmac_secret, created_at) "
        "VALUES (?, ?, ?, ?)",
        (name, next_version, new_secret, now),
    )
    conn.execute(
        "UPDATE principals SET current_version = ?, updated_at = ? WHERE name = ?",
        (next_version, now, name),
    )
    return next_version


def hmac_compare_strings(a: str, b: str) -> bool:
    import hmac as _hmac

    return _hmac.compare_digest(a, b)


def get_secret_for_issuer_version(
    conn: sqlite3.Connection, issuer: str, version: int
) -> str | None:
    """取某主体某历史版本密钥（供已存链按钉扎版本重验）。"""
    row = conn.execute(
        "SELECT hmac_secret FROM principal_keys WHERE name = ? AND version = ?",
        (issuer, version),
    ).fetchone()
    return row["hmac_secret"] if row else None


def save_chain_key_bindings(
    conn: sqlite3.Connection,
    chain_id: str,
    bindings: dict[str, int],
) -> None:
    """把提交事务所内快照到的“签发者 -> 当前密钥版本”钉扎到链上。"""
    now = _now_iso()
    conn.executemany(
        "INSERT INTO chain_key_bindings (chain_id, issuer, key_version, bound_at) "
        "VALUES (?, ?, ?, ?)",
        [(chain_id, issuer, version, now) for issuer, version in bindings.items()],
    )


def load_chain_key_bindings(
    conn: sqlite3.Connection, chain_id: str
) -> dict[str, int]:
    rows = conn.execute(
        "SELECT issuer, key_version FROM chain_key_bindings WHERE chain_id = ?",
        (chain_id,),
    ).fetchall()
    return {r["issuer"]: r["key_version"] for r in rows}


def load_chain_key_binding_records(
    conn: sqlite3.Connection, chain_id: str
) -> list[dict]:
    rows = conn.execute(
        "SELECT issuer, key_version, bound_at FROM chain_key_bindings "
        "WHERE chain_id = ? ORDER BY issuer",
        (chain_id,),
    ).fetchall()
    return [
        {
            "issuer": r["issuer"],
            "key_version": r["key_version"],
            "bound_at": datetime.fromisoformat(r["bound_at"]),
        }
        for r in rows
    ]


class SubmissionSecretResolver:
    """提交时的密钥解析器（在 ``BEGIN IMMEDIATE`` 事务内使用）。

    每个签发者首次取密钥时快照其**当前版本**；该快照一方面立即用于本次验签，
    另一方面随链钉扎落库——因此“验签用哪版密钥”与“链归属哪版密钥”必然一致。
    轮换事务与提交事务靠写锁互斥，不存在跨边界的版本漂移。
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._snapshot: dict[str, int | None] = {}

    def __call__(self, issuer: str) -> str | None:
        if issuer not in self._snapshot:
            self._snapshot[issuer] = principal_current_version(
                self._conn, issuer
            )
        version = self._snapshot[issuer]
        if version is None:
            return None
        return get_secret_for_issuer_version(self._conn, issuer, version)

    def bindings(self) -> dict[str, int]:
        """仅包含解析时确实已注册（取到过版本）的签发者。"""
        return {
            issuer: version
            for issuer, version in self._snapshot.items()
            if version is not None
        }


def bound_secret_lookup(
    conn: sqlite3.Connection, chain_id: str
) -> "Callable[[str], str | None]":
    """已存链的密钥查询：严格按链钉扎版本，忽略主体当前版本。

    未钉扎的签发者（提交时未注册）恒返回 None，保留 ``unknown_issuer``
    的既有结论——主体事后注册 / 轮换都不会让既有无效链复活。
    """
    pinned = load_chain_key_bindings(conn, chain_id)

    def _lookup(issuer: str) -> str | None:
        version = pinned.get(issuer)
        if version is None:
            return None
        return get_secret_for_issuer_version(conn, issuer, version)

    return _lookup


def save_chain(
    conn: sqlite3.Connection,
    submission: ChainSubmission,
    content_sha256: str,
    report: IntegrityReport,
) -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO chains (chain_id, content_sha256, report_json, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            submission.chain_id,
            content_sha256,
            json.dumps(report.model_dump(mode="json"), ensure_ascii=False),
            created_at,
        ),
    )
    conn.executemany(
        "INSERT INTO tokens (chain_id, position, token_json) VALUES (?, ?, ?)",
        [
            (submission.chain_id, i, t.model_dump_json())
            for i, t in enumerate(submission.tokens)
        ],
    )


def get_chain_hash(conn: sqlite3.Connection, chain_id: str) -> str | None:
    row = conn.execute(
        "SELECT content_sha256 FROM chains WHERE chain_id = ?", (chain_id,)
    ).fetchone()
    return row["content_sha256"] if row else None


def load_submission(conn: sqlite3.Connection, chain_id: str) -> ChainSubmission | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    rows = conn.execute(
        "SELECT token_json FROM tokens WHERE chain_id = ? ORDER BY position",
        (chain_id,),
    ).fetchall()
    tokens = [CapabilityToken.model_validate_json(r["token_json"]) for r in rows]
    return ChainSubmission(chain_id=chain_id, tokens=tokens)


def load_chain_record(conn: sqlite3.Connection, chain_id: str) -> dict | None:
    chain = conn.execute(
        "SELECT content_sha256, report_json, created_at FROM chains WHERE chain_id = ?",
        (chain_id,),
    ).fetchone()
    if chain is None:
        return None
    submission = load_submission(conn, chain_id)
    assert submission is not None
    return {
        "chain_id": chain_id,
        "content_sha256": chain["content_sha256"],
        "created_at": datetime.fromisoformat(chain["created_at"]),
        "integrity": IntegrityReport.model_validate(json.loads(chain["report_json"])),
        "tokens": submission.tokens,
        "revocations": load_revocations(conn, chain_id),
        "redemptions": load_redemptions(conn, chain_id),
        "key_bindings": load_chain_key_binding_records(conn, chain_id),
    }


# --------------------------------------------------------------------------- #
# 撤销事件（不可变，只追加）
# --------------------------------------------------------------------------- #
def token_exists(conn: sqlite3.Connection, chain_id: str, token_id: str) -> bool:
    """令牌是否存在于指定链的提交中（按 position 存在性判定，重复 id 也算存在）。"""
    row = conn.execute(
        "SELECT 1 FROM tokens WHERE chain_id = ? "
        "AND json_extract(token_json, '$.token_id') = ? LIMIT 1",
        (chain_id, token_id),
    ).fetchone()
    return row is not None


def load_revocation_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocation_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RevocationEvent | None:
    row = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _revocation_from_row(row) if row else None


def load_revocations(
    conn: sqlite3.Connection, chain_id: str
) -> list[RevocationEvent]:
    """按追加顺序（id 升序）返回某条链的全部撤销事件。"""
    rows = conn.execute(
        "SELECT chain_id, token_id, effective_at, reason, request_key, "
        "content_sha256, created_at FROM revocations WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    return [_revocation_from_row(r) for r in rows]


def insert_revocation(
    conn: sqlite3.Connection,
    event: RevocationEvent,
) -> None:
    """追加一条撤销事件；唯一约束冲突时抛出 sqlite3.IntegrityError（事务回滚）。"""
    conn.execute(
        "INSERT INTO revocations (chain_id, token_id, effective_at, reason, "
        "request_key, content_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.effective_at.astimezone(timezone.utc).isoformat(),
            event.reason,
            event.request_key,
            event.content_sha256,
            event.created_at.astimezone(timezone.utc).isoformat(),
        ),
    )


def _revocation_from_row(row: sqlite3.Row) -> RevocationEvent:
    return RevocationEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        effective_at=datetime.fromisoformat(row["effective_at"]),
        reason=row["reason"],
        request_key=row["request_key"],
        content_sha256=row["content_sha256"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# 一次性访问核销（只在允许且末端时追加，成功记录不可变）
# --------------------------------------------------------------------------- #
_REDEMPTION_COLUMNS = (
    "chain_id, token_id, request_key, request_path, method, source_ip, "
    "request_body, content_sha256, evaluated_at, redeemed_at, created_at"
)


def load_redemption_by_request_key(
    conn: sqlite3.Connection, request_key: str
) -> tuple[RedemptionEvent, str] | None:
    """返回（核销事件, 首次响应 JSON）；未见过该 request_key 时返回 None。"""
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE request_key = ?",
        (request_key,),
    ).fetchone()
    if row is None:
        return None
    return _redemption_from_row(row), row["result_json"]


def load_redemption_for_token(
    conn: sqlite3.Connection, chain_id: str, token_id: str
) -> RedemptionEvent | None:
    """该令牌此前的成功核销记录（同一令牌只能成功核销一次）。"""
    row = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS}, result_json FROM redemptions "
        "WHERE chain_id = ? AND token_id = ?",
        (chain_id, token_id),
    ).fetchone()
    return _redemption_from_row(row) if row else None


def load_redemptions(
    conn: sqlite3.Connection, chain_id: str
) -> list[RedemptionEvent]:
    """按追加顺序（id 升序）返回某条链的全部成功核销记录。"""
    rows = conn.execute(
        f"SELECT {_REDEMPTION_COLUMNS} FROM redemptions "
        "WHERE chain_id = ? ORDER BY id",
        (chain_id,),
    ).fetchall()
    return [_redemption_from_row(r) for r in rows]


def insert_redemption(
    conn: sqlite3.Connection, event: RedemptionEvent, result_json: str
) -> None:
    """追加一条成功核销记录；唯一约束冲突时抛 sqlite3.IntegrityError。"""
    conn.execute(
        "INSERT INTO redemptions (chain_id, token_id, request_key, request_path, "
        "method, source_ip, request_body, content_sha256, evaluated_at, redeemed_at, "
        "created_at, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event.chain_id,
            event.token_id,
            event.request_key,
            event.request_path,
            event.method,
            event.source_ip,
            json.dumps(event.request_body, ensure_ascii=False),
            event.content_sha256,
            event.evaluated_at.astimezone(timezone.utc).isoformat(),
            event.redeemed_at.astimezone(timezone.utc).isoformat(),
            event.created_at.astimezone(timezone.utc).isoformat(),
            result_json,
        ),
    )


def _redemption_from_row(row: sqlite3.Row) -> RedemptionEvent:
    return RedemptionEvent(
        chain_id=row["chain_id"],
        token_id=row["token_id"],
        request_key=row["request_key"],
        request_path=row["request_path"],
        method=row["method"],
        source_ip=row["source_ip"],
        request_body=json.loads(row["request_body"]),
        content_sha256=row["content_sha256"],
        evaluated_at=datetime.fromisoformat(row["evaluated_at"]),
        redeemed_at=datetime.fromisoformat(row["redeemed_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )
