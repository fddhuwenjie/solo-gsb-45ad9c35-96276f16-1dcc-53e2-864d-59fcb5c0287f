"""HMAC 密钥轮换的端到端演示：轮换前/后的签名、提交、求值与核销。

覆盖不变量：
  1. 轮换前提交的链永远按旧密钥重验——查询 / 只读求值 / 首次核销结论不变，撤销照常；
  2. 轮换后新提交的链只按新密钥验签——旧密钥签出的新链 bad_signature；
  3. 已核销请求同键同内容重放仍返回首次结果；任何响应都不含密钥；
  4. 响应只回显主体名与版本号，GET 链记录中的 key_bindings 也只有版本号。

用法：
    # 先启动服务（使用全新数据库，保证 service-a 处于初始 v1）：
    #   docker compose down -v && docker compose up --build
    PYTHONPATH=. python scripts/demo_key_rotation.py
    BASE_URL=http://localhost:8000 PYTHONPATH=. python scripts/demo_key_rotation.py

    重复演示前请重置数据卷（轮换是单向的，旧版本永久保留）：
    #   docker compose down -v && docker compose up --build
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from app.security import compute_signature

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

# 与容器播种的演示主体一致（app.database.DEMO_PRINCIPALS）
ROOT_NAME = "root"
ISSUER_NAME = "service-a"
ROOT_SECRET = os.getenv("ROOT_HMAC_SECRET", "dev-root-secret-change-me")
OLD_SECRET = "demo-secret-service-a"          # 轮换前 service-a 的密钥
NEW_SECRET = "demo-secret-service-a-rotated-2026"  # 轮换后的新密钥

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
OLD_CHAIN_ID = f"demo-rotation-old-{RUN_ID}"     # 轮换前提交
STALE_CHAIN_ID = f"demo-rotation-stale-{RUN_ID}" # 轮换后用旧密钥签的失败链
NEW_CHAIN_ID = f"demo-rotation-new-{RUN_ID}"     # 轮换后用新密钥签的链


def _token(token_id, parent_id, issuer, subject, secret, *, chain_id,
           path_pattern, methods, nb, na, allow_ip=None) -> dict:
    t = {
        "token_id": token_id,
        "parent_id": parent_id,
        "chain_id": chain_id,
        "issuer": issuer,
        "subject": subject,
        "path_pattern": path_pattern,
        "methods": methods,
        "not_before": nb.isoformat().replace("+00:00", "Z"),
        "not_after": na.isoformat().replace("+00:00", "Z"),
        "allow_ip": allow_ip,
        "signature": "",
    }
    t["signature"] = compute_signature(t, secret)
    return t


def build_chain(chain_id: str, issuer_secret: str) -> dict:
    """root -> service-a 的合法两级链，时间窗覆盖当前时刻。"""
    now = datetime.now(timezone.utc)
    nb, na = now - timedelta(days=1), now + timedelta(days=30)
    root = _token(
        "token-root", None, ROOT_NAME, ISSUER_NAME, ROOT_SECRET,
        chain_id=chain_id, path_pattern="/files/**",
        methods=["GET", "POST"], nb=nb, na=na,
    )
    leaf = _token(
        "token-leaf", "token-root", ISSUER_NAME, "service-b-worker", issuer_secret,
        chain_id=chain_id, path_pattern="/files/reports/*",
        methods=["GET"], nb=nb, na=na,
    )
    return {"chain_id": chain_id, "tokens": [root, leaf]}


def evaluation(at: datetime | None = None) -> dict:
    return {
        "request_path": "/files/reports/q1.pdf",
        "method": "GET",
        "at": (at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
    }


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def show(title: str, status: int, body: dict, *, key: str | None = None) -> None:
    print(f"\n=== {title} -> HTTP {status}")
    if key:
        print(json.dumps(body[key], ensure_ascii=False, indent=2))
    else:
        print(json.dumps(body, ensure_ascii=False, indent=2)[:2000])


def assert_no_secret_leak(label: str, body: dict) -> None:
    text = json.dumps(body, ensure_ascii=False)
    assert NEW_SECRET not in text, f"{label} 泄露了新密钥"
    assert OLD_SECRET not in text, f"{label} 泄露了旧密钥"


def main() -> int:
    # 1) 轮换前：用旧密钥签名并提交旧链
    old_chain = build_chain(OLD_CHAIN_ID, OLD_SECRET)
    status, body = request("POST", "/api/v1/chains", old_chain)
    show("1a. 轮换前：旧密钥签名链提交", status, body)
    assert status == 201 and body["integrity"]["allow"] is True

    # 2) 轮换 service-a 的密钥（要求主体处于初始 v1；重跑前请重置数据卷）
    status, body = request(
        "POST", f"/api/v1/principals/{ISSUER_NAME}/keys/rotate",
        {"hmac_secret": NEW_SECRET},
    )
    show("1b. 轮换 service-a 密钥（响应只含版本号，不含密钥）", status, body)
    assert status == 200
    assert body == {
        "name": ISSUER_NAME,
        "previous_version": 1,
        "current_version": 2,
        "rotated_at": body["rotated_at"],
    }
    assert_no_secret_leak("轮换响应", body)

    # 3) 轮换后：旧密钥签出的新链必须验签失败
    stale = build_chain(STALE_CHAIN_ID, OLD_SECRET)
    status, body = request("POST", "/api/v1/chains", stale)
    show("2a. 轮换后：旧密钥签的新链（应 bad_signature）", status, body)
    assert status == 201 and body["integrity"]["allow"] is False
    assert body["integrity"]["first_failed_reason"] == "bad_signature"

    # 4) 轮换后：新密钥签出的新链通过，并钉扎在 v2
    fresh = build_chain(NEW_CHAIN_ID, NEW_SECRET)
    status, body = request("POST", "/api/v1/chains", fresh)
    show("2b. 轮换后：新密钥签的新链（应 allow，钉扎 v2）", status, body)
    assert status == 201 and body["integrity"]["allow"] is True

    # 5) 轮换前的旧链：GET / 求值 / 首次核销全部维持原结论（按 v1 重验）
    status, body = request("GET", f"/api/v1/chains/{OLD_CHAIN_ID}")
    show("3a. 旧链查询：integrity 仍 allow，key_bindings 钉扎 v1", status, body,
         key="key_bindings")
    assert status == 200
    assert body["integrity"]["allow"] is True
    assert {b["issuer"]: b["key_version"] for b in body["key_bindings"]} == {
        ROOT_NAME: 1, ISSUER_NAME: 1,
    }
    assert_no_secret_leak("旧链 GET 响应", body)

    status, body = request(
        "POST", f"/api/v1/chains/{OLD_CHAIN_ID}/evaluate", evaluation()
    )
    show("3b. 旧链只读求值（轮换后仍 allow）", status, body, key="decision")
    assert status == 200 and body["decision"] == "allow"

    redeem_payload = {
        "token_id": "token-leaf",
        "request_key": f"redeem-{RUN_ID}",
        **evaluation(),
    }
    redeem_payload.pop("at")
    status, body = request(
        "POST", f"/api/v1/chains/{OLD_CHAIN_ID}/redeem", redeem_payload
    )
    show("3c. 旧链末端首次核销（钉扎 v1，仍 allow，201）", status, body,
         key="decision")
    assert status == 201 and body["decision"] == "allow" and body["redeemed"] is True
    assert_no_secret_leak("核销响应", body)

    # 6) 已核销请求同键同内容重放：仍返回首次结果
    status, body = request(
        "POST", f"/api/v1/chains/{OLD_CHAIN_ID}/redeem", redeem_payload
    )
    show("3d. 同键同内容重放核销（200，replayed=true，首次结果）", status, body)
    assert status == 200 and body["replayed"] is True and body["decision"] == "allow"

    # 7) 撤销对旧链照常生效（即使其密钥版本是旧的）
    status, body = request(
        "POST", f"/api/v1/chains/{OLD_CHAIN_ID}/revocations",
        {
            "token_id": "token-leaf",
            "effective_at": datetime.now(timezone.utc)
            .isoformat().replace("+00:00", "Z"),
            "reason": "轮换演示：旧链照样可被撤销",
            "request_key": f"revoke-{RUN_ID}",
        },
    )
    show("4a. 对旧链追加立即生效的撤销", status, body, key="affected_token_ids")
    assert status == 201
    status, body = request(
        "POST", f"/api/v1/chains/{OLD_CHAIN_ID}/evaluate", evaluation()
    )
    show("4b. 撤销后旧链求值（应 deny / revoked）", status, body)
    assert body["decision"] == "deny"
    assert body["first_failed_reason"] == "revoked"
    assert_no_secret_leak("撤销后求值响应", body)

    print("\n全部轮换不变量演示通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
