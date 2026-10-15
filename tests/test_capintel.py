"""Capability-intel connector tests: every failure mode is a named refusal.

The risk this connector guards against is not "search returns nothing" - it
is "search fails and the caller cannot tell that apart from nothing found".
So each failure mode asserts three things at once: named status, zero
candidates, and an ``unknown`` finding.
"""
from __future__ import annotations

from pea.capintel import (
    ALLOWED_INTEL_DOMAINS,
    FAILURE_MODES,
    IntelQuery,
    IntelResponse,
    fetch_capability_intel,
)
from pea.tiers import TIER_TOOL_EFFICIENCY

QUERY = IntelQuery(family="dart_aot_snapshot_analysis", keywords=("blutter", "libapp.so"))


def _ok_transport(body: bytes = b"blutter recovers Dart classes\nfrom libapp.so\n") -> IntelResponse:
    def transport(url: str) -> IntelResponse:
        return IntelResponse(status_code=200, headers={"Content-Type": "text/html"}, body=body)

    return transport  # type: ignore[return-value]


def _single_domain(query: IntelQuery = QUERY) -> IntelQuery:
    return IntelQuery(family=query.family, keywords=query.keywords, domains=("github.com",))


# --------------------------------------------------------------------------
# refusal paths
# --------------------------------------------------------------------------


def test_offline_default_is_a_named_unknown_not_empty_success():
    result = fetch_capability_intel(_single_domain())

    assert result.status == "network_unavailable"
    assert result.candidates == ()
    finding = result.findings[0]
    assert finding["status"] == "unknown"
    assert finding["id"] == "capability-intel-unavailable"
    assert result.coverage["state"] == "unavailable"
    assert finding["exposure_tier"] == TIER_TOOL_EFFICIENCY


def test_domain_outside_allowlist_is_refused_before_any_fetch():
    called: list[str] = []

    def transport(url: str) -> IntelResponse:
        called.append(url)
        return IntelResponse(status_code=200, headers={"Content-Type": "text/html"}, body=b"x" * 100)

    result = fetch_capability_intel(_single_domain(), transport=transport, allowlist=frozenset())

    assert result.status == "blocked_domain"
    assert called == []  # refused before the transport runs


def test_redirect_out_of_allowlist_is_refused():
    def transport(url: str) -> IntelResponse:
        return IntelResponse(
            status_code=302,
            headers={"Location": "https://evil.example/next", "Content-Type": "text/html"},
            body=b"",
        )

    result = fetch_capability_intel(_single_domain(), transport=transport)

    assert result.status == "redirect_out_of_allowlist"
    assert result.candidates == ()


def test_transport_exception_is_a_failure_not_a_result():
    def transport(url: str) -> IntelResponse:
        raise OSError("no route to host")

    result = fetch_capability_intel(_single_domain(), transport=transport)

    assert result.status == "all_sources_failed"
    assert result.candidates == ()
    assert result.findings[0]["status"] == "unknown"
    assert any("传输层抛错" in o for o in result.coverage["omissions"])


def test_http_error_is_not_adopted_as_content():
    def transport(url: str) -> IntelResponse:
        return IntelResponse(status_code=404, headers={"Content-Type": "text/html"}, body=b"not found")

    result = fetch_capability_intel(_single_domain(), transport=transport)

    assert result.status == "all_sources_failed"
    assert result.candidates == ()
    assert any("非 2xx" in o for o in result.coverage["omissions"])


def test_oversized_response_is_refused():
    def transport(url: str) -> IntelResponse:
        return IntelResponse(
            status_code=200, headers={"Content-Type": "text/html"}, body=b"x" * (1024 * 1024 + 10)
        )

    result = fetch_capability_intel(_single_domain(), transport=transport)

    assert result.status == "all_sources_failed"
    assert any("超出字节上限" in o for o in result.coverage["omissions"])


def test_unknown_mime_is_refused():
    def transport(url: str) -> IntelResponse:
        return IntelResponse(status_code=200, headers={"Content-Type": "application/octet-stream"}, body=b"binary")

    result = fetch_capability_intel(_single_domain(), transport=transport)

    assert result.status == "all_sources_failed"
    assert any("MIME" in o for o in result.coverage["omissions"])


def test_usable_response_with_no_extractable_items_is_empty_not_success():
    result = fetch_capability_intel(_single_domain(), transport=_ok_transport(b"ab\ncd\n"))

    assert result.status == "empty_result"
    assert result.candidates == ()
    assert result.findings[0]["status"] == "unknown"


def test_every_failure_mode_is_documented():
    for mode, detail in FAILURE_MODES.items():
        assert detail and detail != mode
    for mode in ("network_unavailable", "blocked_domain", "redirect_out_of_allowlist", "all_sources_failed"):
        assert mode in FAILURE_MODES


# --------------------------------------------------------------------------
# success path: claims only
# --------------------------------------------------------------------------


def test_successful_retrieval_yields_external_claims_only():
    result = fetch_capability_intel(_single_domain(), transport=_ok_transport())

    assert result.status == "ok"
    assert result.candidates
    assert {c.authority for c in result.candidates} == {"external_claim"}
    finding = result.findings[0]
    assert finding["status"] == "observed"
    assert finding["evidence"][0]["authority"] == "external_claim"
    assert finding["exposure_tier"] == TIER_TOOL_EFFICIENCY
    # 检索结果不得自带 verified 语义
    assert "external_claim" in " ".join(finding["limitations"])


def test_snippets_are_bounded_and_body_is_not_retained():
    long_line = "x" * 5000

    result = fetch_capability_intel(_single_domain(), transport=_ok_transport(long_line.encode()))

    assert all(len(c.snippet) <= 400 for c in result.candidates)
    assert "body" not in result.to_dict()


def test_partial_failure_is_partial_coverage():
    def transport(url: str) -> IntelResponse:
        if "github.com" in url:
            return IntelResponse(status_code=200, headers={"Content-Type": "text/html"}, body=b"blutter note here")
        return IntelResponse(status_code=500, headers={"Content-Type": "text/html"}, body=b"")

    result = fetch_capability_intel(
        IntelQuery(family="x", domains=("github.com", "gitlab.com")), transport=transport
    )

    assert result.status == "ok"
    assert result.candidates
    assert result.coverage["state"] == "partial"


def test_allowlist_default_covers_the_known_domains():
    for domain in ("github.com", "bbs.kanxue.com", "docs.flutter.dev"):
        assert domain in ALLOWED_INTEL_DOMAINS
    assert "evil.example" not in ALLOWED_INTEL_DOMAINS
