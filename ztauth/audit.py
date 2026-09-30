"""判定审计：记录请求标识、策略版本与判定依据；绝不记录令牌或凭据内容。"""
from __future__ import annotations

import dataclasses
import json
import logging


@dataclasses.dataclass(frozen=True)
class AuditEntry:
    request_id: str
    subject: str
    action: str
    resource: str
    effect: str
    policy_version: int | None
    rationale: str
    release_id: int | None = None


class AuditLogger:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("ztauth.audit")

    def record(self, entry: AuditEntry) -> None:
        payload = dataclasses.asdict(entry)
        # 单行 JSON：便于采集与事后复现；只记录结论性字段
        self._logger.info("ztauth_decision %s", json.dumps(payload, ensure_ascii=False))

    def deny(
        self,
        request_id: str,
        subject: str,
        action: str,
        resource: str,
        reason: str,
        policy_version: int | None = None,
        *,
        release_id: int | None = None,
    ) -> None:
        self.record(
            AuditEntry(
                request_id=request_id,
                subject=subject,
                action=action,
                resource=resource,
                effect="deny",
                policy_version=policy_version,
                rationale=reason,
                release_id=release_id,
            )
        )
