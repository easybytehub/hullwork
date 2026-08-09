"""Asking OSV which of a project's pinned dependencies are known to be vulnerable. Item 172.

**Why this database and not another**, recorded because DR-0016 had to check it before a line was
written: OSV is Apache-2.0, its API needs no key and no account, and it publishes no restriction on
commercial or hosted use. The same check removed CodeQL (free only on open-source code) and
Semgrep's own rule set (internal, non-competing, **non-SaaS**) from consideration on the same day —
either of those would have obliged this product's buyer to pay a competitor, or forbidden the
hosted edition DR-0015 plans.

**It runs in the dispatcher and never in the sandbox.** The attempt has no network by design, and
nothing here is a reason to change that: the question *which versions are affected* is answered
from files on disk plus one host that is not the project's, before a container exists.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

import httpx2

from hullwork.dependencies import Dependency

log = logging.getLogger(__name__)

#: The public instance. Addressed rather than configurable: a vulnerability database an operator
#: could point somewhere else is a supply-chain decision wearing a settings field.
OSV_URL = "https://api.osv.dev"

#: What one batch may carry. The service's own documented limit, and the reason this never sends
#: one request per package — a project with a thousand pins would otherwise be a thousand requests.
BATCH = 1000


@dataclass(frozen=True)
class Advisory:
    """One published vulnerability, and the versions that end it.

    `fixed` is a tuple rather than a single value **on purpose**. An advisory that fixed a problem
    on two release branches publishes two, and picking one would mean comparing versions across two
    ecosystems' ordering rules — a wrong pick there is a bump that does not fix what it claims to.
    All of them are reported and a person decides.
    """

    id: str
    summary: str
    fixed: tuple[str, ...]

    @property
    def has_a_fix(self) -> bool:
        """Whether there is any bump to attempt at all.

        Empty means the advisory publishes no fixed version — not that this failed to find one.
        Proposing the next release and hoping is the guess this project does not make.
        """
        return bool(self.fixed)

    @property
    def url(self) -> str:
        """Where a person reads it themselves, which is the point of naming the id."""
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass(frozen=True)
class Finding:
    """A pinned dependency, and everything published against that exact version."""

    dependency: Dependency
    advisories: tuple[Advisory, ...]


class Osv:
    """The vulnerability database, seen only as "which of these versions are affected?".

    Narrow on purpose, the way `TrackerInventory` is: an object that can only be asked one question
    cannot accidentally be asked another.
    """

    def __init__(self, *, timeout: float = 20.0, transport: object | None = None) -> None:
        self._client = httpx2.Client(
            base_url=OSV_URL,
            headers={"Accept": "application/json"},
            timeout=timeout,
            follow_redirects=False,
            **({"transport": transport} if transport is not None else {}),  # type: ignore[arg-type]
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Osv:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def affected(self, deps: Sequence[Dependency]) -> list[Finding]:
        """Every dependency with something published against its pinned version.

        Two round trips at most per batch: `querybatch` answers with ids only, so the detail —
        which is where the fixing version lives — is fetched once per **id**, not once per package.
        A clean project therefore costs exactly one request.
        """
        findings: list[Finding] = []
        for start in range(0, len(deps), BATCH):
            window = list(deps[start : start + BATCH])
            findings.extend(self._one_batch(window))
        return findings

    def _one_batch(self, window: Sequence[Dependency]) -> list[Finding]:
        queries = [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in window
        ]
        answered = self._post("/v1/querybatch", {"queries": queries})
        results = answered.get("results") if isinstance(answered, dict) else None
        if not isinstance(results, list):
            return []

        # One fetch per distinct id: the same advisory routinely affects several packages, and
        # asking for it once per package would multiply the requests by nothing gained.
        detail: dict[str, dict[str, object]] = {}
        findings: list[Finding] = []
        for dependency, result in zip(window, results, strict=False):
            ids = _ids_in(result)
            if not ids:
                continue
            advisories = []
            for vuln_id in ids:
                if vuln_id not in detail:
                    detail[vuln_id] = self._get(f"/v1/vulns/{vuln_id}")
                advisories.append(_advisory_for(dependency, vuln_id, detail[vuln_id]))
            findings.append(Finding(dependency, tuple(advisories)))
        return findings

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        response = self._client.post(path, json=payload)
        response.raise_for_status()
        body = response.json()
        return body if isinstance(body, dict) else {}

    def _get(self, path: str) -> dict[str, object]:
        response = self._client.get(path)
        response.raise_for_status()
        body = response.json()
        return body if isinstance(body, dict) else {}


def _ids_in(result: object) -> list[str]:
    """The vulnerability ids in one `querybatch` result, which is `{}` when there are none."""
    if not isinstance(result, dict):
        return []
    vulns = result.get("vulns")
    if not isinstance(vulns, list):
        return []
    return [v["id"] for v in vulns if isinstance(v, dict) and isinstance(v.get("id"), str)]


def _advisory_for(
    dependency: Dependency, vuln_id: str, document: dict[str, object]
) -> Advisory:
    """The fixing versions **for this package**, out of an advisory that may name several.

    One advisory routinely covers the same flaw across ecosystems. Reading every `fixed` event in
    the document would hand a PyPI dependency npm's fixing version — a wrong answer that reads as
    entirely plausible in a report, which makes it worse than an obvious one.
    """
    fixed: list[str] = []
    affected = document.get("affected")
    for entry in affected if isinstance(affected, list) else []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        same = package.get("name") == dependency.name
        if not same or package.get("ecosystem") != dependency.ecosystem:
            continue
        ranges = entry.get("ranges")
        for one in ranges if isinstance(ranges, list) else []:
            if not isinstance(one, dict):
                continue
            events = one.get("events")
            for event in events if isinstance(events, list) else []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.append(str(event["fixed"]))

    summary = document.get("summary")
    return Advisory(
        id=vuln_id,
        summary=summary if isinstance(summary, str) else "",
        # De-duplicated, order preserved: two ranges can name the same fixing version.
        fixed=tuple(dict.fromkeys(fixed)),
    )
