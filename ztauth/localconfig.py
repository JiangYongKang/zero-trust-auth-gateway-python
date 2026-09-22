"""本地材料的生成与加载：密钥、策略、凭据全部来自本地目录。

用于本地自验与内部部署，绝不依赖任何远程 KMS/网络。目录布局::

    <dir>/
      keys.json        # 多版本验签密钥（含激活窗口）
      policy.json      # 带 version 的策略文档
      credentials.json # 带版本与状态的凭据集合（明文仅落本地、勿提交）

提供一个 ``python -m ztauth.localconfig init <dir>`` 命令生成一套可直接
运行的演示材料，以及一个 ``mint`` 子命令用本地密钥签发令牌。
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path

from ztauth.credentials import (
    ACTIVE,
    CredentialSet,
    CredentialVault,
    InMemoryCredentialSource,
    make_version,
)
from ztauth.keyring import Key, Keyring, StaticKeySource
from ztauth.policy import (
    HotReloadPolicyEngine,
    FilePolicyStore,
    PolicyDocument,
)
from ztauth.tokens import issue_token

KEYS_FILE = "keys.json"
POLICY_FILE = "policy.json"
CREDS_FILE = "credentials.json"


# ---------------------------------------------------------------------- #
# 序列化
# ---------------------------------------------------------------------- #
def _b64(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    import base64

    return base64.b64decode(text.encode("ascii"))


def dump_keys(keys: list[Key], path: Path) -> None:
    payload = {
        "keys": [
            {
                "kid": k.kid,
                "secret_b64": _b64(k.secret),
                "not_before": k.not_before,
                "not_after": k.not_after,
            }
            for k in keys
        ]
    }
    path.write_text(json.dumps(payload, indent=2))


def load_keys(path: Path) -> list[Key]:
    data = json.loads(path.read_text())
    out: list[Key] = []
    for item in data["keys"]:
        na = item["not_after"]
        out.append(
            Key(
                kid=item["kid"],
                secret=_unb64(item["secret_b64"]),
                not_before=float(item["not_before"]),
                not_after=float("inf") if na in ("inf", None) else float(na),
            )
        )
    return out


def dump_credentials(sets: dict[str, CredentialSet], path: Path) -> None:
    payload = {
        name: {
            "name": name,
            "rotate_interval": cset.rotate_interval,
            "versions": [
                {
                    "version": v.version,
                    "secret": v.secret,
                    "state": v.state,
                    "not_before": v.not_before,
                    "not_after": v.not_after,
                    "read_scopes": sorted(v.read_scopes),
                }
                for v in cset.versions
            ],
        }
        for name, cset in sets.items()
    }
    path.write_text(json.dumps(payload, indent=2))


def load_credentials(path: Path) -> dict[str, CredentialSet]:
    data = json.loads(path.read_text())
    out: dict[str, CredentialSet] = {}
    for name, raw in data.items():
        versions = tuple(
            make_version(
                name,
                int(v["version"]),
                v["secret"],
                state=v.get("state", ACTIVE),
                not_before=float(v.get("not_before", 0.0)),
                not_after=(
                    float("inf")
                    if v.get("not_after") in ("inf", None)
                    else float(v["not_after"])
                ),
                read_scopes=v.get("read_scopes", []),
            )
            for v in raw["versions"]
        )
        out[name] = CredentialSet(
            name=name,
            versions=versions,
            rotate_interval=float(raw.get("rotate_interval", 0.0)),
        )
    return out


# ---------------------------------------------------------------------- #
# 组装网关
# ---------------------------------------------------------------------- #
def build_gateway(material_dir: str | Path, *, overlap_seconds: float = 60.0):
    """从本地目录组装一个完整 :class:`AuthGateway`（策略走文件热更新）。"""
    base = Path(material_dir)
    keys = load_keys(base / KEYS_FILE)
    keyring = Keyring(
        StaticKeySource(keys), overlap_seconds=overlap_seconds, clock=time.time
    )
    policies = HotReloadPolicyEngine(FilePolicyStore(base / POLICY_FILE))
    source = _FileCredentialSource(base / CREDS_FILE)
    vault = CredentialVault(source, clock=time.time)
    from ztauth.engine import AuthGateway

    return AuthGateway(keyring, policies, vault, clock=time.time), keyring, policies, vault


class _FileCredentialSource(InMemoryCredentialSource):
    """基于 credentials.json 的来源；reload 时重新读盘。"""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self._path = path

    def load(self) -> dict:
        sets = load_credentials(self._path)
        self.replace_all(sets)
        return super().load()


# ---------------------------------------------------------------------- #
# CLI：本地材料初始化与签发
# ---------------------------------------------------------------------- #
def init_material_dir(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    now = time.time()
    k1 = Key(kid="key-2026-01", secret=secrets.token_bytes(32),
             not_before=0.0, not_after=now + 30 * 86400)
    dump_keys([k1], target / KEYS_FILE)

    policy = {
        "version": 1,
        "rules": [
            {
                "id": "allow-alice-read-db",
                "effect": "allow",
                "action": "read",
                "resource": "db",
                "principal_attr": "sub",
                "principal_in": ["alice"],
                "requires": ["dept"],
            },
            {
                "id": "deny-bob-read-db",
                "effect": "deny",
                "action": "read",
                "resource": "db",
                "principal_attr": "sub",
                "principal_in": ["bob"],
            },
        ],
    }
    (target / POLICY_FILE).write_text(json.dumps(policy, indent=2))

    cred = CredentialSet(
        name="db",
        versions=(
            make_version(
                "db", 1, "local-demo-secret-" + secrets.token_hex(8),
                state=ACTIVE, read_scopes=["db:read"],
            ),
        ),
    )
    dump_credentials({"db": cred}, target / CREDS_FILE)
    print(f"initialized local material directory: {target}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ztauth.localconfig")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="generate a local material directory")
    p_init.add_argument("dir")
    p_mint = sub.add_parser("mint", help="mint a token using a local key set")
    p_mint.add_argument("dir")
    p_mint.add_argument("--sub", default="alice")
    p_mint.add_argument("--ttl", type=float, default=300.0)
    p_mint.add_argument("--scope", action="append", default=["db:read"])
    p_mint.add_argument("--attr", action="append", default=["dept=eng"])
    args = parser.parse_args(argv)

    if args.cmd == "init":
        init_material_dir(Path(args.dir))
        return 0

    keys = load_keys(Path(args.dir) / KEYS_FILE)
    keyring = Keyring(StaticKeySource(keys), overlap_seconds=60.0, clock=time.time)
    attrs = dict(a.split("=", 1) for a in args.attr)
    token, claims = issue_token(
        keyring, sub=args.sub, ttl_seconds=args.ttl,
        scopes=set(args.scope), attributes=attrs,
    )
    print(token)
    print(f"# kid={claims.kid} sub={claims.sub} exp={claims.expires_at:.0f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
