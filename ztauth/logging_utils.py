"""日志工具：请求标识、策略版本、判定依据的结构化输出与敏感信息脱敏。"""

from __future__ import annotations

import contextvars
import logging
import re
from typing import Any

#: 已知敏感键名，其值一律脱敏
SENSITIVE_KEYS = frozenset({"secret", "token", "password", "credential", "key", "mac"})

_REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_POLICY_VERSION: contextvars.ContextVar[str] = contextvars.ContextVar(
    "policy_version", default="-"
)

#: 粗略匹配可能的令牌/密钥形态，用于消息内容兜底脱敏
_SECRETISH = re.compile(r"[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{24,}")


def set_request_context(request_id: str, policy_version: int | str = "-") -> tuple[Any, Any]:
    """设置当前上下文的请求标识与策略版本，返回 reset token。"""
    raise NotImplementedError


def reset_request_context(tokens: tuple[Any, Any]) -> None:
    raise NotImplementedError


def redact(value: Any) -> str:
    """把任意值转为不含敏感材料的安全字符串。"""
    raise NotImplementedError


class RequestContextFilter(logging.Filter):
    """为每条日志注入 request_id 与 policy_version 字段。"""

    def filter(self, record: logging.LogRecord) -> bool:
        raise NotImplementedError


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """配置 ztauth 日志器：单行结构化输出 + 上下文注入 + 脱敏。"""
    raise NotImplementedError


def get_logger(name: str = "ztauth") -> logging.Logger:
    raise NotImplementedError
