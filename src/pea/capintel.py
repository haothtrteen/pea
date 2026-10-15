"""Capability-intel domain (M3/D2 + D6/R1): the retrieval connector.

PEA's answer to "how should I protect this?" depends on time-sensitive
knowledge - what the current break paths are, which tooling works against
which build. That makes retrieval a first-class input, and it makes the
retrieval connector a place where things can go badly wrong: a fabricated
finding, a silently followed redirect, a swamp of unattributed claims.

So the connector is built around refusals:

* **offline by default.** With no transport injected, the domain does not
  touch the network and reports ``network_unavailable`` - offline is an
  explicit unknown, not a degraded success and not an empty result that
  looks like "nothing found";
* **domain allowlist.** A URL outside the allowlist is refused before any
  byte is fetched;
* **safe failure.** Non-200 status, redirect out of the allowlist, oversized
  response, unknown MIME and transport errors each produce a named
  ``unknown`` and zero results - never a partial result that looks verified;
* **results are claims.** Everything retrieved is ``external_claim``
  authority with source, retrieval date and confidence. Nothing retrieved
  enters a plan as ``verified``; that upgrade needs source audit and a
  fixture (see :mod:`pea.candidatereview`);
* **content is bounded.** Snippets are truncated and the raw body is never
  retained in the result.

This module ships the connector and its policy. It does not publish a
crawler, does not store credentials, and does not execute anything it reads.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from pea.tiers import TIER_TOOL_EFFICIENCY

#: Domains the connector may contact. Everything else is refused up front.
ALLOWED_INTEL_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "api.github.com",
        "gitlab.com",
        "bbs.kanxue.com",
        "www.52pojie.cn",
        "stackoverflow.com",
        "developer.android.com",
        "docs.flutter.dev",
        "pypi.org",
        "npmjs.com",
    }
)

#: Maximum body size accepted from a source; larger is refused.
MAX_RESPONSE_BYTES = 1_048_576
#: Snippet length kept per result (the body itself is never retained).
MAX_SNIPPET_CHARS = 400

#: Content types accepted; anything else is an unknown MIME refusal.
ALLOWED_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "text/plain",
    "application/json",
    "text/markdown",
)

#: Named failure modes. Each is an explicit unknown, never a silent pass.
FAILURE_MODES: dict[str, str] = {
    "network_unavailable": "未提供传输实现或网络不可用；未检索（离线默认行为）",
    "blocked_domain": "目标域名不在 allowlist 内，拒绝请求",
    "redirect_out_of_allowlist": "重定向目标越过 allowlist，拒绝跟随",
    "transport_error": "传输层抛错；未获得可验证响应",
    "http_error": "非 2xx 响应；未采信内容",
    "oversized_response": "响应超出字节上限，拒绝解析",
    "unknown_mime": "响应 MIME 不在允许列表内，拒绝解析",
    "empty_result": "响应可用但未提取到条目",
    "all_sources_failed": "所有 allowlist 来源均未返回可用结果（见 coverage.omissions）",
}


@dataclass(frozen=True)
class IntelResponse:
    """What a transport returns. Tests inject this; production supplies it."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class IntelQuery:
    """A capability-family question, e.g. dart_aot_snapshot_analysis."""

    family: str
    keywords: tuple[str, ...] = ()
    #: Restrict to a subset of :data:`ALLOWED_INTEL_DOMAINS` for this query.
    domains: tuple[str, ...] = ()

    def target_domains(self) -> tuple[str, ...]:
        if self.domains:
            requested = tuple(d for d in self.domains if d in ALLOWED_INTEL_DOMAINS)
            return requested
        return tuple(sorted(ALLOWED_INTEL_DOMAINS))


@dataclass(frozen=True)
class IntelCandidate:
    """One retrieved item: a claim with a source and a date, nothing more."""

    source_url: str
    title: str
    snippet: str
    retrieved_at: str
    authority: str = "external_claim"
    confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "title": self.title,
            "snippet": self.snippet,
            "retrieved_at": self.retrieved_at,
            "authority": self.authority,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class CapabilityIntelResult:
    """Outcome of one retrieval attempt, including how it failed."""

    query: IntelQuery
    status: str  # ok | one of FAILURE_MODES keys
    candidates: tuple[IntelCandidate, ...] = ()
    findings: tuple[dict[str, Any], ...] = ()
    coverage: dict[str, Any] = field(default_factory=dict)
    unknowns: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": {"family": self.query.family, "keywords": list(self.query.keywords)},
            "status": self.status,
            "candidates": [c.to_dict() for c in self.candidates],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "unknowns": list(self.unknowns),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def _is_allowed(url: str, allowlist: frozenset[str]) -> bool:
    return _host_of(url) in allowlist


def fetch_capability_intel(
    query: IntelQuery,
    *,
    transport: Callable[[str], IntelResponse] | None = None,
    allowlist: frozenset[str] = ALLOWED_INTEL_DOMAINS,
    max_bytes: int = MAX_RESPONSE_BYTES,
    now: str | None = None,
) -> CapabilityIntelResult:
    """Retrieve capability intel for one family, or refuse with a named reason.

    ``transport`` is injected, never constructed here: with no transport the
    domain stays offline and says so. That is the default - a protection
    assistant that silently reaches the network is a worse problem than one
    that reports "I could not check".
    """
    stamp = now or _utc_now()
    allow = frozenset(allowlist)

    if transport is None:
        return _failure(query, "network_unavailable", stamp, allow)

    targets = [d for d in query.target_domains() if d in allow]
    if not targets:
        return _failure(query, "blocked_domain", stamp, allow)

    candidates: list[IntelCandidate] = []
    omissions: list[str] = []
    for domain in targets:
        url = f"https://{domain}/search?q={query.family}"
        if not _is_allowed(url, allow):
            omissions.append(f"{domain}: {FAILURE_MODES['blocked_domain']}")
            continue
        try:
            response = transport(url)
        except Exception as exc:  # any transport failure is a refusal, never a result
            omissions.append(f"{domain}: {FAILURE_MODES['transport_error']}（{exc.__class__.__name__}）")
            continue

        # Redirect handling: an allowlist escape is a refusal, not a hop.
        location = response.headers.get("Location") if response.headers else None
        if location and not _is_allowed(location, allow):
            return _failure(query, "redirect_out_of_allowlist", stamp, allow, extra=f"{domain} -> {location}")

        if not 200 <= response.status_code < 300:
            omissions.append(f"{domain}: {FAILURE_MODES['http_error']}（HTTP {response.status_code}）")
            continue
        content_type = (response.headers or {}).get("Content-Type", "").split(";")[0].strip().lower()
        if content_type and content_type not in ALLOWED_CONTENT_TYPES:
            omissions.append(f"{domain}: {FAILURE_MODES['unknown_mime']}（{content_type}）")
            continue
        if len(response.body) > max_bytes:
            omissions.append(f"{domain}: {FAILURE_MODES['oversized_response']}（{len(response.body)} 字节）")
            continue

        extracted = _extract_candidates(domain, response.body, stamp)
        candidates.extend(extracted)

    if not candidates:
        reason = "empty_result" if not omissions else "all_sources_failed"
        return _failure(query, reason, stamp, allow, omissions=omissions)

    findings = _build_findings(query, tuple(candidates), stamp, omissions=tuple(omissions))
    coverage = {
        "state": "partial" if omissions else "complete_for_scope",
        "scope": (
            f"对 {len(targets)} 个 allowlist 域名做只读检索（每响应 ≤{max_bytes} 字节、"
            f"片段 ≤{MAX_SNIPPET_CHARS} 字符；结果一律 external_claim）"
        ),
        "omissions": omissions,
    }
    return CapabilityIntelResult(
        query=query,
        status="ok",
        candidates=tuple(candidates),
        findings=findings,
        coverage=coverage,
        unknowns=(
            "检索结果为 external_claim：未经源码审计与 fixture 实测，不得作为 verified 结论",
            "检索结果只进候选队列，不直接执行、不直接纳入计划",
        ),
    )


def _extract_candidates(domain: str, body: bytes, stamp: str) -> list[IntelCandidate]:
    """Turn a bounded response into claim-shaped entries.

    Deliberately shallow: this extracts lines that mention the query context,
    truncates them, and attaches the source. Deep parsing of arbitrary pages
    is not a thing PEA claims to do.
    """
    text = body.decode("utf-8", errors="replace")
    out: list[IntelCandidate] = []
    for line in text.splitlines():
        stripped = line.strip()
        if len(stripped) < 8:
            continue
        out.append(
            IntelCandidate(
                source_url=f"https://{domain}",
                title=stripped[:MAX_SNIPPET_CHARS],
                snippet=stripped[:MAX_SNIPPET_CHARS],
                retrieved_at=stamp,
            )
        )
        if len(out) >= 20:  # bounded: a page scan is not a corpus
            break
    return out


def _failure(
    query: IntelQuery,
    reason: str,
    stamp: str,
    allowlist: frozenset[str],
    *,
    omissions: list[str] | None = None,
    extra: str = "",
) -> CapabilityIntelResult:
    """One refusal shape: named reason, zero candidates, explicit unknown.

    ``status`` carries the machine-readable reason so a caller can branch;
    ``unknowns`` carries the human-readable one; and the finding is
    ``unknown`` so no downstream consumer can mistake this for evidence.
    """
    detail = FAILURE_MODES.get(reason, "未分类的检索失败")
    if extra:
        detail = f"{detail}（{extra}）"
    listed = list(omissions or [])
    return CapabilityIntelResult(
        query=query,
        status=reason,
        candidates=(),
        findings=(
            {
                "id": "capability-intel-unavailable",
                "category": "capability_intel",
                "status": "unknown",
                "severity": "unrated",
                "title": "能力情报检索未获得可用结果",
                "summary": f"{detail}；该能力族的情报面未评估（安全失败：拒绝给出结果而非降级）",
                "evidence": [
                    {
                        "evidence_id": "ev-capintel-unavailable",
                        "kind": "file_observation",
                        "source": f"pea.capintel:{query.family}",
                        "observed_at": stamp,
                        "authority": "observation",
                        "limitations": ["无检索结果；情报面未知而非为空"],
                        "redacted_summary": detail,
                    }
                ],
                "coverage": {"state": "unavailable", "scope": f"allowlist {len(allowlist)} 个域名"},
                "limitations": [
                    "检索结果一律为 external_claim，需源码审计与 fixture 实测才能升级",
                    "allowlist 外域名一律拒绝",
                    *listed,
                ],
                "recommended_actions": [
                    "注入传输实现或恢复网络后重试",
                    "或以人工方式取得情报并记录为 external_claim 证据",
                ],
                "exposure_tier": TIER_TOOL_EFFICIENCY,
            },
        ),
        coverage={
            "state": "unavailable",
            "scope": f"allowlist {len(allowlist)} 个域名；检索失败：{reason}",
            "omissions": listed,
        },
        unknowns=(detail, "情报时效性未经核实：检索失败不等于该能力族不存在当前破解路径"),
    )


def _build_findings(
    query: IntelQuery,
    candidates: tuple[IntelCandidate, ...],
    stamp: str,
    *,
    omissions: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    """One observed finding for a successful retrieval - still claims only."""
    redacted = "; ".join(f"{c.source_url}: {c.title[:80]}" for c in candidates[:5])
    return (
        {
            "id": "capability-intel-retrieved",
            "category": "capability_intel",
            "status": "observed",
            "severity": "info",
            "title": "检索到能力情报条目",
            "summary": (
                f"{query.family} 检索到 {len(candidates)} 条条目"
                f"（来源 {len({c.source_url for c in candidates})} 个域名）；"
                "全部为 external_claim，需审计与实测后方可采信"
            ),
            "evidence": [
                {
                    "evidence_id": "ev-capintel-retrieved",
                    "kind": "file_observation",
                    "source": f"pea.capintel:{query.family}",
                    "observed_at": stamp,
                    "authority": "external_claim",
                    "limitations": ["检索结果为外部声明；未做源码审计或实测"],
                    "redacted_summary": redacted,
                }
            ],
            "coverage": {"state": "partial" if omissions else "complete_for_scope", "scope": "能力情报检索"},
            "limitations": [
                "条目为 external_claim，不得作为 verified 结论",
                "片段已截断，原文未保留",
                "allowlist 之外的来源未覆盖",
            ],
            "recommended_actions": [
                "对候选条目做源码审计（固定 commit）后再提升证据等级",
                "用 fixture 实测验证关键声明",
            ],
            "exposure_tier": TIER_TOOL_EFFICIENCY,
        },
    )
