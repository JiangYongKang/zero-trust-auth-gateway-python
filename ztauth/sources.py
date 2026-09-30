"""本地源：内存密钥源 / JSON 文件策略源 / 内存发布批次源。"""
from __future__ import annotations

import json
import pathlib

from .keys import SigningKey
from .policy import Policy, Rule
from .releases import ReleaseContent


class MutableKeySource:
    """测试/本地用密钥源；set_keys 后 KeyRing 未知 kid 重载即可见到新集合。"""

    def __init__(self, keys: list[SigningKey], version: int) -> None:
        self._keys = keys
        self._version = version
        self.load_count = 0

    def set_keys(self, keys: list[SigningKey], version: int) -> None:
        self._keys = keys
        self._version = version

    def load(self) -> tuple[list[SigningKey], int]:
        self.load_count += 1
        return list(self._keys), self._version


class FailingKeySource:
    """模拟密钥源不可用。"""

    def __init__(self, keys: list[SigningKey], version: int) -> None:
        self._keys = keys
        self._version = version

    def load(self) -> tuple[list[SigningKey], int]:
        raise ConnectionError("key source down")


def parse_key_row(row: dict) -> SigningKey:
    import datetime as dt
    return SigningKey(
        kid=row["kid"],
        secret=row["secret"].encode(),
        not_before=dt.datetime.fromisoformat(row["not_before"]),
        not_after=dt.datetime.fromisoformat(row["not_after"]),
        state=row.get("state", "active"),
    )


class JsonPolicySource:
    """每次 load 重新读盘：文件改写后 PolicyStore.reload 即可热生效。"""

    def __init__(self, path: str | pathlib.Path) -> None:
        self.path = pathlib.Path(path)

    def load(self) -> Policy:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        rules = tuple(
            Rule(
                id=r["id"],
                effect=r["effect"],
                action=r["action"],
                resource=r["resource"],
                require=dict(r.get("require", {})),
                roles=tuple(r.get("roles", ())),
            )
            for r in data["rules"]
        )
        return Policy(version=int(data["version"]), rules=rules)


class MutableReleaseSource:
    """测试/本地用发布源：set_content 后 publish/受控回源即可见到新整批。

    load_count 统计真正的上游读取次数（构造期可选择不计），用于断言
    "同批并发只真正读取一次"与"未知 kid 冲击下读取次数有上限"。
    """

    def __init__(self, content: ReleaseContent) -> None:
        self._content = content
        self.load_count = 0

    def set_content(self, content: ReleaseContent) -> None:
        self._content = content

    def load(self) -> ReleaseContent:
        self.load_count += 1
        return self._content
