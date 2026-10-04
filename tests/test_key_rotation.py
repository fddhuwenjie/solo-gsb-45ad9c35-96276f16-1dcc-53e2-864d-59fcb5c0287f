"""HMAC 密钥轮换：版本钉扎、旧链结论冻结、并发归属与密钥不泄露。"""
from __future__ import annotations

import itertools
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import engine as engine_module
from app.database import get_conn, principal_current_version
from app.security import compute_signature

_seq = itertools.count(1)


def _raw_token(
    token_id, parent_id, issuer, subject, chain_id,
    path_pattern="/files/reports/*", methods=("GET", "POST"),
    not_before="2026-01-01T00:00:00Z", not_after="2026-12-31T23:59:59Z",
    allow_ip=None, secret="",
) -> dict:
    """按给定密钥构造令牌（不依赖 conftest 的固定 SECRETS 表）。"""
    t = {
        "token_id": token_id,
        "parent_id": parent_id,
        "chain_id": chain_id,
        "issuer": issuer,
        "subject": subject,
        "path_pattern": path_pattern,
        "methods": list(methods),
        "not_before": not_before,
        "not_after": not_after,
        "allow_ip": allow_ip,
        "signature": "",
    }
    t["signature"] = compute_signature(t, secret)
    return t


@pytest.fixture()
def principals(client):
    """为每个用例注册一对互不干扰的主体：自定义根 + 委托方。

    会话级共享 DB，轮换会推进版本，故不能复用固定主体；
    根主体名通过临时修改引擎配置指向本用例的唯一根名。
    """
    n = next(_seq)
    root_name, deleg_name = f"rot-root-{n}", f"rot-a-{n}"
    root_secret, deleg_secret = f"secret-root-{n}", f"secret-a-{n}"
    for name, secret in ((root_name, root_secret), (deleg_name, deleg_secret)):
        resp = client.post(
            "/api/v1/principals",
            json={"name": name, "hmac_secret": secret},
        )
        assert resp.status_code == 201, resp.text
    original = engine_module.settings.root_principal
    object.__setattr__(engine_module.settings, "root_principal", root_name)
    try:
        yield {
            "root": root_name,
            "deleg": deleg_name,
            "root_secret": root_secret,
            "deleg_secret": deleg_secret,
            "secrets": {root_name: root_secret, deleg_name: deleg_secret},
        }
    finally:
        object.__setattr__(
            engine_module.settings, "root_principal", original
        )


def _chain2(client, principals, *, root_secret=None, deleg_secret=None) -> dict:
    """root -> deleg 的两级链；root/deleg 名取自该用例的独立主体。"""
    chain_id = f"chain-rot-{next(_seq)}"
    root_name, deleg_name = principals["root"], principals["deleg"]
    root = _raw_token(
        "root", None, root_name, deleg_name, chain_id,
        path_pattern="/files/**", methods=("GET", "POST"),
        secret=root_secret or principals["root_secret"],
    )
    child = _raw_token(
        "child", "root", deleg_name, "rot-b", chain_id,
        path_pattern="/files/reports/*", methods=("GET",),
        secret=deleg_secret or principals["deleg_secret"],
    )
    return {"chain_id": chain_id, "tokens": [root, child]}


def _rotate(client, name, secret):
    return client.post(
        f"/api/v1/principals/{name}/keys/rotate",
        json={"hmac_secret": secret},
    )


def _evaluate(client, chain_id, *, at="2026-06-01T00:00:00Z", path="/files/reports/x"):
    return client.post(
        f"/api/v1/chains/{chain_id}/evaluate",
        json={"request_path": path, "method": "GET", "at": at},
    )


def _live_chain(principals) -> dict:
    """时间窗覆盖当前时刻的 root -> child 链，供核销用。"""
    chain_id = f"chain-rot-{next(_seq)}"
    now = datetime.now(timezone.utc)
    nb = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    na = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    root = _raw_token(
        "root", None, principals["root"], principals["deleg"], chain_id,
        path_pattern="/files/**", methods=("GET",),
        not_before=nb, not_after=na,
        secret=principals["root_secret"],
    )
    child = _raw_token(
        "child", "root", principals["deleg"], "rot-b", chain_id,
        path_pattern="/files/reports/*", methods=("GET",),
        not_before=nb, not_after=na,
        secret=principals["deleg_secret"],
    )
    return {"chain_id": chain_id, "tokens": [root, child]}


# --------------------------------------------------------------------------- #
# 接口基本语义
# --------------------------------------------------------------------------- #
def test_rotate_unknown_principal_404(client):
    resp = _rotate(client, "nobody-never-registered", "whatever")
    assert resp.status_code == 404
    assert "nobody-never-registered" in resp.json()["detail"]


def test_rotate_same_secret_conflicts_and_is_noop(client, principals):
    name = principals["deleg"]
    resp = _rotate(client, name, principals["deleg_secret"])
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    # 冲突细节只含主体名与版本号，不含任何密钥
    assert principals["deleg_secret"] not in json.dumps(detail, ensure_ascii=False)
    assert detail["current_version"] == 1
    with get_conn() as conn:
        assert principal_current_version(conn, name) == 1
        assert conn.execute(
            "SELECT COUNT(*) AS c FROM principal_keys WHERE name = ?", (name,)
        ).fetchone()["c"] == 1


def test_rotate_success_returns_versions_without_secret(client, principals):
    resp = _rotate(client, principals["deleg"], "rotated-v2")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == principals["deleg"]
    assert body["previous_version"] == 1
    assert body["current_version"] == 2
    assert body["rotated_at"]
    text = json.dumps(body, ensure_ascii=False)
    assert "rotated-v2" not in text
    assert "hmac_secret" not in text and "secret" not in text.lower().replace("rotated_at", "")


def test_rotate_advances_versions_each_time(client, principals):
    name = principals["deleg"]
    r1 = _rotate(client, name, "a-v2")
    assert r1.status_code == 200 and r1.json()["current_version"] == 2
    r2 = _rotate(client, name, "a-v3")
    assert r2.status_code == 200
    assert r2.json()["previous_version"] == 2
    assert r2.json()["current_version"] == 3


# --------------------------------------------------------------------------- #
# 轮换后：新提交按新密钥；旧密钥签的新链不通过
# --------------------------------------------------------------------------- #
def test_new_submission_after_rotation_uses_new_secret(client, principals):
    assert _rotate(client, principals["deleg"], "rotated-deleg").status_code == 200

    # 旧密钥签出的新链：child 验签失败
    old_signed = _chain2(client, principals)
    resp = client.post("/api/v1/chains", json=old_signed)
    assert resp.status_code == 201
    report = resp.json()["integrity"]
    assert report["allow"] is False
    assert report["first_failed_node"] == "child"
    assert report["first_failed_reason"] == "bad_signature"

    # 新密钥签出的链：通过
    good = _chain2(client, principals, deleg_secret="rotated-deleg")
    ok = client.post("/api/v1/chains", json=good)
    assert ok.status_code == 201
    assert ok.json()["integrity"]["allow"] is True
    # 新链钉扎在 v2
    record = client.get(f"/api/v1/chains/{good['chain_id']}").json()
    assert {b["issuer"]: b["key_version"] for b in record["key_bindings"]} == {
        principals["root"]: 1,
        principals["deleg"]: 2,
    }


def test_root_principal_can_rotate_too(client, principals):
    assert _rotate(client, principals["root"], "rotated-root").status_code == 200
    # 根令牌仍用旧根密钥签 -> 根节点即报 bad_signature
    payload = _chain2(client, principals)
    body = client.post("/api/v1/chains", json=payload).json()["integrity"]
    assert body["first_failed_node"] == "root"
    assert body["first_failed_reason"] == "bad_signature"
    # 根用新密钥、委托方仍用原密钥 -> 全部通过
    good = _chain2(
        client, principals, root_secret="rotated-root"
    )
    assert client.post("/api/v1/chains", json=good).json()["integrity"][
        "allow"
    ] is True


# --------------------------------------------------------------------------- #
# 轮换前保存的链：继续用旧密钥重验，结论完全冻结
# --------------------------------------------------------------------------- #
def test_pre_rotation_chain_keeps_old_verdict_in_query_and_evaluate(client, principals):
    payload = _chain2(client, principals)
    assert client.post("/api/v1/chains", json=payload).status_code == 201
    assert _rotate(client, principals["deleg"], "rotated-x").status_code == 200

    # GET 中提交时的完整性报告不变，钉扎信息可见（不含密钥）
    record = client.get(f"/api/v1/chains/{payload['chain_id']}").json()
    assert record["integrity"]["allow"] is True
    bindings = {b["issuer"]: b["key_version"] for b in record["key_bindings"]}
    assert bindings == {principals["root"]: 1, principals["deleg"]: 1}
    assert "hmac_secret" not in json.dumps(record["key_bindings"])

    # 只读求值实时重算时仍按钉扎 v1 验签 -> allow
    ev = _evaluate(client, payload["chain_id"])
    assert ev.status_code == 200
    assert ev.json()["decision"] == "allow"
    sig_checks = [
        c for n in ev.json()["trace"] for c in n["checks"]
        if c["name"] == "signature"
    ]
    assert all(c["passed"] for c in sig_checks)


def test_pre_rotation_invalid_chain_does_not_become_valid(client, principals):
    """既有无效链不能因新密钥恰好匹配而变成有效。"""
    # child 的签发者在提交时**尚未注册**：unknown_issuer，链落库为无效
    ghost_name = f"rot-ghost-{next(_seq)}"
    chain_id = f"chain-rot-{next(_seq)}"
    root = _raw_token(
        "root", None, principals["root"], ghost_name, chain_id,
        path_pattern="/files/**", methods=("GET", "POST"),
        secret=principals["root_secret"],
    )
    # 为满足“issuer == 父 subject”，根的被授权主体也要是 ghost_name
    child = _raw_token(
        "child", "root", ghost_name, "rot-b", chain_id,
        path_pattern="/files/reports/*", methods=("GET",),
        secret="ghosts-first-secret",
    )
    payload = {"chain_id": chain_id, "tokens": [root, child]}
    first = client.post("/api/v1/chains", json=payload)
    assert first.json()["integrity"]["allow"] is False
    assert first.json()["integrity"]["first_failed_reason"] == "unknown_issuer"

    # 之后注册该主体（v1 密钥恰好就是误签密钥），再轮换：旧链钉扎的是“未注册”，
    # 结论不允许翻转
    reg = client.post(
        "/api/v1/principals",
        json={"name": ghost_name, "hmac_secret": "ghosts-first-secret"},
    )
    assert reg.status_code == 201
    assert _rotate(client, ghost_name, "ghosts-second-secret").status_code == 200
    record = client.get(f"/api/v1/chains/{chain_id}").json()
    assert record["integrity"]["allow"] is False
    assert record["integrity"]["first_failed_reason"] == "unknown_issuer"
    assert ghost_name not in {b["issuer"] for b in record["key_bindings"]}
    ev = _evaluate(client, chain_id)
    assert ev.json()["decision"] == "deny"
    assert ev.json()["first_failed_reason"] == "unknown_issuer"

    # 同一把“恰好匹配”的密钥新签另一条链提交：按已注册主体的密钥验签，正常通过
    other_id = f"chain-rot-{next(_seq)}"
    root2 = _raw_token(
        "root", None, principals["root"], ghost_name, other_id,
        path_pattern="/files/**", methods=("GET", "POST"),
        secret=principals["root_secret"],
    )
    child2 = _raw_token(
        "child", "root", ghost_name, "rot-b", other_id,
        path_pattern="/files/reports/*", methods=("GET",),
        secret="ghosts-second-secret",
    )
    ok = client.post(
        "/api/v1/chains", json={"chain_id": other_id, "tokens": [root2, child2]}
    )
    assert ok.json()["integrity"]["allow"] is True


def test_pre_rotation_bad_signature_chain_does_not_become_valid(client, principals):
    """已注册主体密钥误签的链（bad_signature），轮换到同密钥后仍无效。

    链钉扎的是提交时的 v1；即便运维把 v2 新密钥设成与误签串一致，
    旧链只按 v1 重验，不允许“碰巧有效”。
    """
    accidental = "accidental-equals-new-secret"
    payload = _chain2(client, principals, deleg_secret=accidental)
    first = client.post("/api/v1/chains", json=payload)
    assert first.json()["integrity"]["allow"] is False
    assert first.json()["integrity"]["first_failed_reason"] == "bad_signature"

    assert _rotate(client, principals["deleg"], accidental).status_code == 200
    # 钉扎在 v1（签发者当时已注册），v1 仍是原密钥，误签永不通过
    record = client.get(f"/api/v1/chains/{payload['chain_id']}").json()
    binding = {b["issuer"]: b["key_version"] for b in record["key_bindings"]}
    assert binding[principals["deleg"]] == 1
    assert record["integrity"]["allow"] is False
    assert _evaluate(client, payload["chain_id"]).json()["decision"] == "deny"


def test_revocation_still_enforced_on_old_chain_after_rotation(client, principals):
    payload = _chain2(client, principals)
    chain_id = payload["chain_id"]
    assert client.post("/api/v1/chains", json=payload).status_code == 201
    assert _rotate(client, principals["deleg"], "rotated-rev").status_code == 200

    revoked = client.post(
        f"/api/v1/chains/{chain_id}/revocations",
        json={
            "token_id": "child",
            "effective_at": "2026-03-01T00:00:00Z",
            "reason": "轮换后仍可撤销旧链",
            "request_key": f"rk-rot-rev-{next(_seq)}",
        },
    )
    assert revoked.status_code == 201
    after = _evaluate(client, chain_id, at="2026-06-01T00:00:00Z")
    assert after.json()["decision"] == "deny"
    assert after.json()["first_failed_node"] == "child"
    assert after.json()["first_failed_reason"] == "revoked"
    before = _evaluate(client, chain_id, at="2026-02-01T00:00:00Z")
    assert before.json()["decision"] == "allow"


def test_first_redeem_after_rotation_uses_pinned_old_secret(client, principals):
    payload = _live_chain(principals)
    chain_id = payload["chain_id"]
    assert client.post("/api/v1/chains", json=payload).status_code == 201
    assert _rotate(client, principals["deleg"], "rotated-redeem").status_code == 200

    resp = client.post(
        f"/api/v1/chains/{chain_id}/redeem",
        json={
            "token_id": "child",
            "request_key": f"rk-rot-first-{next(_seq)}",
            "request_path": "/files/reports/x",
            "method": "GET",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["decision"] == "allow"
    assert resp.json()["redeemed"] is True


def test_redeemed_request_same_key_replays_first_result_after_rotation(
    client, principals
):
    payload = _live_chain(principals)
    chain_id = payload["chain_id"]
    assert client.post("/api/v1/chains", json=payload).status_code == 201
    key = f"rk-rot-replay-{next(_seq)}"
    redeem_body = {
        "token_id": "child", "request_key": key,
        "request_path": "/files/reports/x", "method": "GET",
    }
    first = client.post(f"/api/v1/chains/{chain_id}/redeem", json=redeem_body)
    assert first.status_code == 201
    assert _rotate(client, principals["deleg"], "rotated-replay").status_code == 200

    second = client.post(f"/api/v1/chains/{chain_id}/redeem", json=redeem_body)
    assert second.status_code == 200
    s, f = second.json(), first.json()
    assert s["replayed"] is True
    assert s["decision"] == f["decision"] == "allow"
    assert s["redeemed_at"] == f["redeemed_at"]
    assert s["trace"] == f["trace"]


# --------------------------------------------------------------------------- #
# 提交与轮换并发：链的密钥归属必须与提交时验签结果一致
# --------------------------------------------------------------------------- #
def test_concurrent_submit_and_rotate_binding_matches_verdict(client, principals):
    n = 10
    outcomes: list[tuple[bool, str]] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(n + 1)
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            barrier.wait()
            payload = _chain2(client, principals)  # 全部用轮换前旧密钥签名
            resp = client.post("/api/v1/chains", json=payload)
            with lock:
                outcomes.append(
                    (resp.json()["integrity"]["allow"], payload["chain_id"])
                )
        except BaseException as exc:  # 重新在主线程抛出，避免静默
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    barrier.wait()  # 与所有 worker 同时放行轮换，制造交错
    rotate_resp = _rotate(client, principals["deleg"], "rotated-concurrent")
    for t in threads:
        t.join()
    assert rotate_resp.status_code == 200
    assert not errors, errors
    assert len(outcomes) == n

    for allow, chain_id in outcomes:
        record = client.get(f"/api/v1/chains/{chain_id}").json()
        binding = {b["issuer"]: b["key_version"] for b in record["key_bindings"]}
        # 不变量：钉扎版本与该提交验签所用的当前版本严格一致——
        # 轮换先落库 => 钉扎 v2，旧密钥签名按 v2 验为 bad_signature；
        # 轮换后落库 => 钉扎 v1，旧密钥签名通过。
        if allow:
            assert binding.get(principals["deleg"]) == 1
        else:
            assert binding.get(principals["deleg"]) == 2
        # 事后查询 / 求值结论与提交时一致，不因后续再轮换而翻转
        ev = _evaluate(client, chain_id)
        assert ev.json()["decision"] == ("allow" if allow else "deny")
        assert (ev.json()["first_failed_reason"] is None) == allow


def test_rotation_failure_leaves_no_partial_switch(client, principals):
    name = principals["deleg"]
    bad = _rotate(client, name, principals["deleg_secret"])
    assert bad.status_code == 409
    with get_conn() as conn:
        assert principal_current_version(conn, name) == 1
        assert conn.execute(
            "SELECT COUNT(*) AS c FROM principal_keys WHERE name = ?", (name,)
        ).fetchone()["c"] == 1
    ok = _rotate(client, name, "rotated-after-failed-attempt")
    assert ok.status_code == 200
    assert ok.json()["current_version"] == 2


def test_submission_replay_after_rotation_revalidates_with_pinned_secret(
    client, principals
):
    payload = _chain2(client, principals)
    assert client.post("/api/v1/chains", json=payload).status_code == 201
    assert _rotate(client, principals["deleg"], "rotated-submit-replay").status_code == 200

    replay = client.post("/api/v1/chains", json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["integrity"]["allow"] is True


# --------------------------------------------------------------------------- #
# 旧版数据库自动迁移
# --------------------------------------------------------------------------- #
def test_legacy_single_column_secret_db_migrates_and_pins_v1():
    """旧库 principals(name,hmac_secret) 经 init_db 迁移到版本化结构，
    既有链回填 v1 钉扎，且迁移后轮换不改变旧链验签。"""
    import os
    import sqlite3
    import tempfile

    from app import database as db_module

    path = os.path.join(tempfile.mkdtemp(prefix="rot-mig-"), "legacy.db")
    raw = sqlite3.connect(path)
    raw.executescript(
        """
        CREATE TABLE principals (name TEXT PRIMARY KEY, hmac_secret TEXT NOT NULL);
        CREATE TABLE chains (chain_id TEXT PRIMARY KEY, content_sha256 TEXT NOT NULL,
            report_json TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE tokens (chain_id TEXT NOT NULL, position INTEGER NOT NULL,
            token_json TEXT NOT NULL, PRIMARY KEY (chain_id, position));
        INSERT INTO principals VALUES ('root', 'legacy-root-secret');
        INSERT INTO principals VALUES ('svc-a', 'legacy-a-secret');
        INSERT INTO chains VALUES ('leg-c', 'h', '{}', '2026-01-01T00:00:00+00:00');
        INSERT INTO tokens VALUES ('leg-c', 0, '{"token_id":"r","issuer":"root"}');
        INSERT INTO tokens VALUES ('leg-c', 1, '{"token_id":"x","issuer":"svc-a"}');
        INSERT INTO tokens VALUES ('leg-c', 2, '{"token_id":"g","issuer":"ghost"}');
        """
    )
    raw.commit()
    raw.close()

    conn = db_module.connect(path)
    try:
        db_module.init_db(conn)  # 触发迁移（幂等：再调一次也不报错）
        db_module.init_db(conn)

        assert db_module.principal_current_version(conn, "root") == 1
        assert db_module.get_secret(conn, "svc-a") == "legacy-a-secret"

        pinned = db_module.load_chain_key_bindings(conn, "leg-c")
        assert pinned == {"root": 1, "svc-a": 1}  # ghost 未注册不回填

        lookup = db_module.bound_secret_lookup(conn, "leg-c")
        assert lookup("root") == "legacy-root-secret"
        assert lookup("ghost") is None

        # 迁移后的库上做轮换：当前密钥变化，旧链仍取历史 v1
        conn.execute("BEGIN IMMEDIATE")
        new_v = db_module.rotate_principal_secret(conn, "root", "legacy-root-v2")
        conn.commit()
        assert new_v == 2
        assert db_module.get_secret(conn, "root") == "legacy-root-v2"
        assert db_module.bound_secret_lookup(conn, "leg-c")("root") == (
            "legacy-root-secret"
        )
    finally:
        conn.close()
