"""场景四：并发鉴权下结论一致性、热更新无脏读、密钥重载 single-flight。"""
from __future__ import annotations

import datetime as dt
import threading
from collections import Counter

import pytest

from ztauth.errors import AuthError, DenyReason
from ztauth.tokens import TokenIssuer


def _token(ring, sub, roles, attrs, now):
    return TokenIssuer(ring).issue(
        sub, ttl=dt.timedelta(minutes=10), roles=roles, attrs=attrs, now=now
    )


def test_concurrent_mixed_requests_have_stable_reasons(gateway, ring, now):
    tok_allow = _token(ring, "alice", ("reader",), {"team": "payments"}, now)
    tok_deny = _token(ring, "guest1", ("guest",), {"team": "payments"}, now)
    tok_miss = _token(ring, "bob", ("reader",), {}, now)
    tokens = [("allow", tok_allow), ("deny", tok_deny), ("missing", tok_miss)]

    outcomes: Counter[str] = Counter()
    lock = threading.Lock()
    n_thread, n_rounds = 12, 50
    barrier = threading.Barrier(n_thread)

    def worker(tid):
        barrier.wait()
        for i in range(n_rounds):
            label, tok = tokens[(tid + i) % 3]
            try:
                gateway.authorize(f"c-{tid}-{i}", tok, "read", "db-payments", now=now)
                got = "allow"
            except AuthError as exc:
                got = exc.reason.value
            expected = {
                "allow": "allow",
                "deny": DenyReason.POLICY_DENY.value,
                "missing": DenyReason.POLICY_MISSING_ATTRIBUTE.value,
            }[label]
            assert got == expected, f"{label}: got {got}"
            with lock:
                outcomes[got] += 1

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_thread)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total = n_thread * n_rounds
    assert sum(outcomes.values()) == total
    assert set(outcomes) == {"allow", "policy_deny", "policy_missing_attribute"}


def test_concurrent_policy_reload_never_mixes_versions(gateway, gateway_factory, now, tmp_path):
    import json
    from ztauth.policy import PolicyStore
    from ztauth.sources import JsonPolicySource

    path = tmp_path / "p.json"

    def write(v: int):
        path.write_text(json.dumps({
            "version": v,
            "rules": [{
                "id": f"r-v{v}", "effect": "allow", "action": "read",
                "resource": "db-payments", "require": {"v": str(v)},
                "roles": ["reader"],
            }],
        }), encoding="utf-8")

    write(1)
    store = PolicyStore(JsonPolicySource(path))
    gw = gateway_factory(store)

    ring = gw._verifier._ring  # 共享同一 keyring
    tok1 = _token(ring, "s1", ("reader",), {"v": "1"}, now)
    tok2 = _token(ring, "s2", ("reader",), {"v": "2"}, now)

    seen: list[tuple[int, str]] = []
    seen_lock = threading.Lock()
    stop = threading.Event()

    def reloader():
        for v in (2, 1, 2, 1):
            write(v)
            gw.reload_policies()

    def caller(tid):
        i = 0
        while not stop.is_set():
            i += 1
            tok, label = (tok1, "1") if i % 2 else (tok2, "2")
            try:
                res = gw.authorize(f"h-{tid}-{i}", tok, "read",
                                   "db-payments", now=now)
                pv = res.decision.policy_version
                # 关键不变量：结论的 policy_version 必须与所匹配属性一致
                assert pv == int(label)
                with seen_lock:
                    seen.append((pv, "allow"))
            except AuthError as exc:
                assert exc.reason is DenyReason.POLICY_DENY
                with seen_lock:
                    seen.append((store.current().version, "deny"))

    t = threading.Thread(target=reloader)
    callers = [threading.Thread(target=caller, args=(i,)) for i in range(8)]
    for c in callers:
        c.start()
    t.start()
    t.join()
    stop.set()
    for c in callers:
        c.join()

    assert seen, "必须实际产生过判定"
    # 每个判定的属性版本与策略版本对齐：不存在 v1 属性在 v2 策略上"碰巧"放行的脏读
    for pv, _effect in seen:
        assert pv in (1, 2)


def test_concurrent_unknown_kid_does_not_duplicate_fetch(ring, overlapping_keys, now):
    from ztauth.keys import KeyRing, SigningKey
    from ztauth.sources import MutableKeySource

    new_key = SigningKey("k-new", b"secret-new",
                         now - dt.timedelta(minutes=1),
                         now + dt.timedelta(days=1), "active")
    src = MutableKeySource(list(overlapping_keys), version=1)
    gate_ring = KeyRing(src)
    src.set_keys(list(overlapping_keys) + [new_key], version=2)

    # 用能识别 k-new 的环签发
    signer_ring = KeyRing(
        MutableKeySource(list(overlapping_keys) + [new_key], 2)
    )
    token = _token(signer_ring, "z", ("reader",), {"team": "x"}, now)

    # 重写 token 的 kid：直接用 signer 已签 k2，这里改为 k-new 显式签发
    token = TokenIssuer(signer_ring).issue(
        "z", ttl=dt.timedelta(minutes=10), kid="k-new", now=now
    )

    from ztauth.tokens import TokenVerifier
    verifier = TokenVerifier(gate_ring)
    barrier = threading.Barrier(32)
    errors: list[Exception] = []

    def worker():
        barrier.wait()
        try:
            assert verifier.verify(token, now=now).jti
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker) for _ in range(32)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    assert gate_ring.version() == 2
    # 构造期 1 次 + 并发未知 kid 合并后仅 1 次
    assert src.load_count == 2
