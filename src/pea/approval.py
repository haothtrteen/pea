"""短时一次性批准令牌：绑定 plan digest、工件 digest、参数与工具版本。

Phase 3 的验收原话："建立绑定 plan digest、工件 digest、参数和版本的短时
一次性批准。验收：计划变化、令牌过期/重放、路径越界都拒绝。" 本模块就是
这句话的代码化：

* **一次性**——消耗过的令牌 id 进入已消耗集合，重放直接拒绝
  （``token_replayed``），不存在"同意的复用"；
* **短时**——TTL 由权威实例持有，时钟可注入；过期拒绝
  （``token_expired``），测试用固定时钟推进时间，不靠 sleep；
* **绑定**——签发时把作用域（工具、plan digest、工件 digest、规范化参数
  digest、工具版本、授权根、目标路径）全部钉进令牌；消耗时逐字段比对，
  任何变化都是拒绝（``scope_mismatch``），计划改了就必须重新审；
* **路径越界**——签发时目标路径必须位于授权根之内（``path_outside_
  authorized_root``）；授权根本身也是绑定字段，换个根来消耗同样拒绝。

令牌 id 由密钥 + 单调 nonce 派生：同一进程内同一作用域的两次签发得到
不同 id（否则重放检测会把第二次误判为重放）。密钥与时钟都可注入——生产
用随机密钥与真实时钟，测试用固定值换取确定性。

WP0 增加的第二道边界：**令牌签发必须挂一个审批事件**。事件由可信通道
产生（CLI 交互确认 / 操作员 shell 的 ``pea approve``），带作用域指纹，
按磁盘上的事件存储落盘、消费即焚。模型给的 Boolean（``authorization`` /
``explicit_user_approval``）只是意图表达，不再是充分条件——这是执行器
接线的前置条件：agent 无法自助审批。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

#: 默认 TTL：短到足够一次交互，长到足够用户确认后马上使用。
DEFAULT_TTL_SECONDS = 900


class ApprovalError(Exception):
    """A refused approval. ``reason`` is a stable named code, never prose."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _canonical(obj: Any) -> str:
    """A stable textual form for digests: sorted keys, no whitespace games."""
    import json

    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _atomic_write_json(path: Path, payload: Any) -> None:
    """Atomic JSON write (temp file + rename): a reader never sees half a file."""
    import json
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def args_digest(args: Any) -> str:
    """Digest of the exact arguments an approval covers."""
    return hashlib.sha256(_canonical(args).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalScope:
    """Everything an approval is bound to. All fields are compared on consume."""

    tool: str
    plan_digest: str
    artifact_digest: str
    args_digest: str
    tool_version: str
    authorized_root: str
    target_path: str
    issued_at: datetime
    expires_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "plan_digest": self.plan_digest,
            "artifact_digest": self.artifact_digest,
            "args_digest": self.args_digest,
            "tool_version": self.tool_version,
            "authorized_root": self.authorized_root,
            "target_path": self.target_path,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


@dataclass(frozen=True)
class ApprovalToken:
    """An opaque handle plus the scope it carries. Never construct directly."""

    token_id: str
    scope: ApprovalScope

    def to_dict(self) -> dict[str, Any]:
        return {"token_id": self.token_id, "scope": self.scope.to_dict()}


#: The scope fields an approval event covers - the same fields the token
#: binds, minus the timestamps (audit metadata, never reproducible by a
#: caller that did not witness the issuance).
_SCOPE_FINGERPRINT_FIELDS = (
    "tool",
    "plan_digest",
    "artifact_digest",
    "args_digest",
    "tool_version",
    "authorized_root",
    "target_path",
)


def scope_fingerprint(
    *,
    tool: str,
    plan_digest: str,
    artifact_digest: str,
    args_digest: str,
    tool_version: str,
    authorized_root: str | Path,
    target_path: str | Path,
) -> str:
    """Stable fingerprint of an approval scope.

    The fingerprint is what a trusted approval channel shows the operator
    and what token issuance later checks: approving fingerprint X approves
    exactly the scope X, nothing looser.
    """
    payload = {
        "tool": tool,
        "plan_digest": plan_digest,
        "artifact_digest": artifact_digest,
        "args_digest": args_digest,
        "tool_version": tool_version,
        "authorized_root": str(authorized_root),
        "target_path": str(target_path),
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ApprovalEvent:
    """A trusted-channel decision to approve one exact scope fingerprint.

    Produced only by a trusted channel (the operator's own shell: ``pea
    approve`` after seeing the full scope, or the inline confirmation of
    ``pea protect``). An MCP agent can request a preview; it cannot
    register an event.
    """

    event_id: str
    fingerprint: str
    decided_at: str
    decided_by: str
    consumed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "fingerprint": self.fingerprint,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "consumed": self.consumed,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ApprovalEvent:
        return cls(
            event_id=str(data["event_id"]),
            fingerprint=str(data["fingerprint"]),
            decided_at=str(data.get("decided_at", "")),
            decided_by=str(data.get("decided_by", "")),
            consumed=bool(data.get("consumed", False)),
        )


class ApprovalAuthority:
    """Issues and consumes short-lived one-time tokens for one server process.

    Token issuance requires a registered :class:`ApprovalEvent` whose
    fingerprint matches the scope being issued; the event is consumed by
    the issuance (one approval, one token). Events live in an optional
    on-disk store so an operator's ``pea approve`` in their own shell can
    satisfy a token request that arrives later over MCP.
    """

    def __init__(
        self,
        *,
        secret: bytes | None = None,
        clock: Callable[[], datetime] | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        event_store: str | Path | None = None,
    ) -> None:
        if ttl_seconds < 1:
            raise ApprovalError("token_ttl_invalid", f"ttl_seconds={ttl_seconds}")
        self._secret = secret if secret is not None else secrets.token_bytes(32)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ttl = timedelta(seconds=ttl_seconds)
        self._issued: dict[str, ApprovalToken] = {}
        self._consumed: set[str] = set()
        self._nonce = 0
        self._event_store = Path(event_store).expanduser().resolve() if event_store else None
        #: This process's own view of registered events. The disk store is
        #: the cross-process channel (operator shell <-> MCP server); the
        #: in-memory list serves single-process flows (``pea protect``
        #: confirms and issues in one process). An MCP server never
        #: registers events itself, so this list stays empty there.
        self._events: list[ApprovalEvent] = []

    # -- approval events (the trusted-channel half) ------------------------

    def register_approval(self, *, fingerprint: str, decided_by: str = "cli:interactive") -> ApprovalEvent:
        """Record a trusted approval of exactly ``fingerprint``.

        Written to the event store (one JSON file per event) so the
        approval survives across processes: the operator's shell and the
        MCP server do not share memory, only this store. Without a
        configured store the event lives in this process's own view only -
        which is exactly right for the single-process ``pea protect`` flow
        and useless (by design) for a cross-process agent request.
        """
        if not fingerprint:
            raise ApprovalError("approval_fingerprint_missing", "refusing to register an empty fingerprint")
        event = ApprovalEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            fingerprint=fingerprint,
            decided_at=self._clock().isoformat(timespec="seconds"),
            decided_by=decided_by,
        )
        self._events.append(event)
        if self._event_store is not None:
            self._event_store.mkdir(parents=True, exist_ok=True)
            path = self._event_store / f"{event.event_id}.json"
            _atomic_write_json(path, event.to_dict())
        return event

    def approval_for(self, fingerprint: str) -> ApprovalEvent | None:
        """The unconsumed event approving ``fingerprint``, if any.

        The shared disk store is the truth when one is configured: an event
        registered (or consumed) by another process must be visible here,
        so a process-local view can never outlive the store. Without a
        store the in-memory list serves the single-process flow. One
        approval, one token: a consumed event never satisfies a second
        issuance.
        """
        if not fingerprint:
            return None
        if self._event_store is not None and self._event_store.is_dir():
            for path in sorted(self._event_store.glob("evt-*.json")):
                try:
                    event = ApprovalEvent.from_dict(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError, KeyError, ValueError):
                    continue
                if event.fingerprint == fingerprint and not event.consumed:
                    return event
            return None
        for event in reversed(self._events):
            if event.fingerprint == fingerprint and not event.consumed:
                return event
        return None

    def _consume_event(self, event: ApprovalEvent) -> None:
        """Mark an event consumed - in this process and on disk."""
        consumed = ApprovalEvent(
            event_id=event.event_id,
            fingerprint=event.fingerprint,
            decided_at=event.decided_at,
            decided_by=event.decided_by,
            consumed=True,
        )
        self._events = [consumed if e.event_id == event.event_id else e for e in self._events]
        if self._event_store is None:
            return
        path = self._event_store / f"{event.event_id}.json"
        if path.is_file():
            _atomic_write_json(path, consumed.to_dict())

    # -- issuance ---------------------------------------------------------

    def issue(
        self,
        *,
        tool: str,
        plan_digest: str,
        artifact_digest: str,
        args_digest: str,
        tool_version: str,
        authorized_root: str | Path,
        target_path: str | Path,
        approval_event: ApprovalEvent | None = None,
    ) -> ApprovalToken:
        """Bind a scope and mint a one-time token. Path escape refuses here.

        Issuance requires a trusted :class:`ApprovalEvent` covering
        exactly this scope: no event, or an event for a different scope,
        is a named refusal - a caller cannot talk itself into an approval.
        """
        root = Path(authorized_root).resolve()
        target = Path(target_path).resolve()
        if root != target and root not in target.parents:
            raise ApprovalError(
                "path_outside_authorized_root",
                f"target={target} is outside authorized root {root}",
            )
        if approval_event is None:
            raise ApprovalError(
                "approval_event_missing",
                "令牌签发必须挂可信通道产生的审批事件（pea approve / protect 交互确认）；调用方自述授权不算审批",
            )
        wanted = scope_fingerprint(
            tool=tool,
            plan_digest=plan_digest,
            artifact_digest=artifact_digest,
            args_digest=args_digest,
            tool_version=tool_version,
            authorized_root=root,
            target_path=target,
        )
        if approval_event.fingerprint != wanted:
            raise ApprovalError(
                "approval_scope_mismatch",
                f"审批事件覆盖 {approval_event.fingerprint}，本次签发需要 {wanted}——批准必须逐字节对应",
            )
        self._consume_event(approval_event)
        now = self._clock()
        self._nonce += 1
        token_id = self._derive(tool, plan_digest, artifact_digest, args_digest, tool_version, root, target, now, self._nonce)
        scope = ApprovalScope(
            tool=tool,
            plan_digest=plan_digest,
            artifact_digest=artifact_digest,
            args_digest=args_digest,
            tool_version=tool_version,
            authorized_root=str(root),
            target_path=str(target),
            issued_at=now,
            expires_at=now + self._ttl,
        )
        token = ApprovalToken(token_id=token_id, scope=scope)
        self._issued[token_id] = token
        return token

    def _derive(self, *parts: Any) -> str:
        message = "|".join(str(part) for part in parts).encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()[:32]

    # -- consumption ------------------------------------------------------

    def consume(self, token_id: str, expected: ApprovalScope) -> ApprovalScope:
        """Spend a token against an expected scope; refuse loudly otherwise.

        Returns the consumed scope on success. Every refusal is a named
        :class:`ApprovalError` reason - a refusal is never a silent pass.
        ``issued_at``/``expires_at`` are authority-side audit metadata, not
        binding fields: expiry is checked against the clock, and the caller
        cannot reproduce timestamps it never saw.
        """
        token = self._issued.get(token_id)
        if token is None:
            raise ApprovalError("token_unknown", token_id)
        if token_id in self._consumed:
            raise ApprovalError("token_replayed", token_id)
        now = self._clock()
        if now > token.scope.expires_at:
            raise ApprovalError("token_expired", f"expired_at={token.scope.expires_at.isoformat()}")
        for field_name in (
            "tool",
            "plan_digest",
            "artifact_digest",
            "args_digest",
            "tool_version",
            "authorized_root",
            "target_path",
        ):
            bound = getattr(token.scope, field_name)
            wanted = getattr(expected, field_name)
            if bound != wanted:
                raise ApprovalError(
                    "scope_mismatch",
                    f"{field_name}: bound={bound!r} expected={wanted!r}",
                )
        self._consumed.add(token_id)
        return token.scope

    # -- introspection ----------------------------------------------------

    def outstanding(self) -> tuple[str, ...]:
        """Issued-but-unconsumed token ids (for audit, never for reuse)."""
        return tuple(tid for tid in self._issued if tid not in self._consumed)
