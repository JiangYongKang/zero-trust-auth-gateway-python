"""日志工具：请求标识、策略版本、判定依据的结构化输出与敏感信息脱敏。

约定
====

* 每条日志单行、key=value 风格，固定附带 ``request_id`` 与
  ``policy_version`` 上下文字段，便于把一次判定的全部事件串联起来。
* 敏感信息零泄露：:func:`redact` 对已知敏感键名（token/secret/key/
  password/credential/mac）与疑似令牌形态（两段长 base64url）统一替换
  为 ``"***REDACTED***"``。
* 上下文通过 :class:`contextvars.ContextVar` 传播，天然兼容
  ``asyncio`` 与线程池场景（每请求各自隔离）。
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any

#: 已知敏感键名（小写匹配），其值一律脱敏
SENSITIVE_KEYS = frozenset(
    {"secret", "token", "password", "passwd", "credential", "key", "mac",
     "authorization"}
)
REDACTED = "***REDACTED***"

_REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="-"
)
_POLICY_VERSION: contextvars.ContextVar[str] = contextvars.ContextVar(
    "policy_version", default="-"
)

#: 疑似令牌形态：至少 16 个 base64url 字符的两段（payload.mac）
def _looks_like_token(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 2:
        return False
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    return len(parts[0]) >= 16 and len(parts[1]) >= 16 and all(
        c in allowed for c in text if c != "."
    )


def set_request_context(
    request_id: str, policy_version: int | str = "-"
) -> tuple[contextvars.Token[str], contextvars.Token[str]]:
    """设置当前上下文的请求标识与策略版本，返回用于还原的 token 对。"""
    t1 = _REQUEST_ID.set(request_id or "-")
    t2 = _POLICY_VERSION.set(str(policy_version))
    return t1, t2


def reset_request_context(
    tokens: tuple[contextvars.Token[str], contextvars.Token[str]]
) -> None:
    """还原 :func:`set_request_context` 之前的上下文。"""
    t1, t2 = tokens
    _REQUEST_ID.reset(t1)
    _POLICY_VERSION.reset(t2)


def current_request_id() -> str:
    return _REQUEST_ID.get()


def current_policy_version() -> str:
    return _POLICY_VERSION.get()


def redact(value: Any, *, key: str | None = None) -> str:
    """把任意值转为不含敏感材料的安全字符串。

    已知敏感键名直接脱敏；字符串若呈现令牌形态也脱敏；其余值做普通
    ``str()`` 转换但截断到合理长度，避免意外倾倒大体量内容。
    """
    if key is not None and key.lower() in SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, str):
        if _looks_like_token(value):
            return REDACTED
        # 对映射风格字符串 "token=xxxx" 做兜底
        lowered = value.lower()
        for name in SENSITIVE_KEYS:
            needle = f"{name}="
            idx = lowered.find(needle)
            if idx != -1:
                return value[: idx + len(needle)] + REDACTED
        return value if len(value) <= 512 else value[:512] + "...<truncated>"
    if isinstance(value, (bytes, bytearray)):
        return REDACTED
    text = str(value)
    return text if len(text) <= 512 else text[:512] + "...<truncated>"


def safe_kwargs(**kwargs: Any) -> str:
    """把结构化字段渲染成安全的 ``key=value`` 日志片段。"""
    parts = []
    for k, v in kwargs.items():
        parts.append(f"{k}={redact(v, key=k)}")
    return " ".join(parts)


class RequestContextFilter(logging.Filter):
    """为每条日志记录注入 request_id / policy_version 字段。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _REQUEST_ID.get()
        record.policy_version = _POLICY_VERSION.get()
        return True


class _RedactingFormatter(logging.Formatter):
    """对最终日志消息做一次令牌形态兜底脱敏。"""

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        # 逐 token 检查，替换疑似两段式令牌
        cleaned = []
        for word in text.split(" "):
            bare = word.strip(",;:")
            if _looks_like_token(bare):
                cleaned.append(word.replace(bare, REDACTED))
            else:
                cleaned.append(word)
        return " ".join(cleaned)


_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """配置 ztauth 日志器：单行结构化输出 + 上下文注入 + 脱敏。

    幂等：重复调用不会叠加 handler。
    """
    global _CONFIGURED
    logger = logging.getLogger("ztauth")
    logger.setLevel(level)
    if not _CONFIGURED:
        handler = logging.StreamHandler()
        fmt = (
            "%(asctime)s %(levelname)s logger=%(name)s "
            "request_id=%(request_id)s policy_version=%(policy_version)s "
            "%(message)s"
        )
        handler.setFormatter(_RedactingFormatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S"))
        handler.addFilter(RequestContextFilter())
        logger.addHandler(handler)
        logger.propagate = False
        _CONFIGURED = True
    return logger


def get_logger(name: str = "ztauth") -> logging.Logger:
    """获取 ztauth 层级 logger（未配置时退化为不输出的安全默认）。"""
    logger = logging.getLogger(name if name == "ztauth" else f"ztauth.{name}")
    if not _CONFIGURED:
        configure_logging()
    return logger
