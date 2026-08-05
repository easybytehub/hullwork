"""GlitchTip's read API.

Every shape below was confirmed against a live GlitchTip 6.2.2 on 2026-07-27, not taken from
documentation — which is just as well, because the documentation does not describe this API and two
of the confirmations changed the code:

* the detail routes answer in **camelCase** (`lineNo`, `absPath`, `dateCreated`) while the
  **event** list route answers in snake_case and omits `eventID` entirely. One parser for both would
  be wrong in both directions, so each route gets its own;
* the paginated helper emits its `Link` header wrapped in **Python set syntax** — a real bug, on
  every list response — and no RFC 5988 parser will accept it. Nothing here paginates: the samples
  route is unpaginated at small limits, and `list_unresolved` pages by time instead.

Amended 2026-07-30 (item 080, DR-0011). This adapter now **does** touch a list route — the issue
list, which the inventory sweep needs because the outbound webhook speaks once per issue and never
again. Two corrections came out of measuring it, and they are recorded here because the paragraph
above had been read as forbidding it:

* the *issue* list route answers **camelCase** (`firstSeen`, `lastSeen`, `numComments`, `shortId`).
  The snake_case claim was true of the event list route and had been over-generalised to all of
  them;
* the broken `Link` header is real and still there, re-measured. That is a reason not to *paginate*,
  which `list_unresolved` does not — it asks for one bounded page and pages by time.

Least privilege is `event:read` **alone**, verified: every route used here accepts it, and every
mutating route requires strictly more. The credential this replaces held all sixteen scopes and
could delete any issue or project in the organisation.
"""

import logging
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import httpx2

from hullwork.scrub import Scrubber
from hullwork.tracker import (
    FetchedEvent,
    Frame,
    PermanentTrackerError,
    RetryableTrackerError,
    TrackerIssue,
)

log = logging.getLogger(__name__)

#: Anything at or above this is worth another go. Note GlitchTip does **not** rate-limit its read
#: API — 40 sequential reads all returned 200 with no `Retry-After` — so 429 is here for the proxy
#: somebody will eventually put in front of it, not for the application.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

_NOT_FOUND = 404

#: The issue id inside a permalink, e.g. `http://tracker/org/issues/6`. Parsing this here rather
#: than in core is the point of the adapter boundary: the shape of a provider's URL is exactly the
#: kind of knowledge that must not leak upwards.
_ISSUE_IN_PERMALINK = re.compile(r"/issues/(\d+)")

#: How much of a stack to keep. Deep stacks are mostly framework, and an agent handed two hundred
#: frames reads none of them.
MAX_FRAMES = 40

#: Locals are the most valuable field for a reproduction and the most dangerous one. Bounded so a
#: single frame holding a large object cannot turn one event into a stored megabyte.
MAX_VAR_CHARS = 2000

#: A `(lineno, source)` pair, which is how the detail route serialises source context.
_PAIR = 2

#: Sorts an issue with no `lastSeen` first rather than crashing the comparison. Item 080.
_EPOCH = datetime.fromtimestamp(0, tz=UTC)


def _utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _tags(payload: Mapping[str, Any]) -> dict[str, str]:
    """GlitchTip carries release, environment and server name as tags, not as fields."""
    out: dict[str, str] = {}
    for tag in payload.get("tags") or []:
        if isinstance(tag, dict) and tag.get("key") is not None:
            out[str(tag["key"])] = str(tag.get("value", ""))
    return out


def _entry(payload: Mapping[str, Any], kind: str) -> Mapping[str, Any] | None:
    for entry in payload.get("entries") or []:
        if isinstance(entry, dict) and entry.get("type") == kind:
            data = entry.get("data")
            if isinstance(data, dict):
                return data
    return None


class GlitchTipTracker:
    """Reads events from a GlitchTip instance. Holds an `event:read` token and nothing more."""

    def __init__(self, base_url: str, token: str, timeout: float = 15.0, *,
                 organisation: str = "", scrubber: Scrubber | None = None) -> None:
        self._client = httpx2.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=timeout,
            follow_redirects=False,
        )
        # Shapes on: this is the path where an audit found a live DSN inside `sys.argv`, in a field
        # no name-based rule would ever have flagged. The token itself is registered by value so a
        # tracker that ever echoed it back could not store it here.
        self._scrub = scrubber or Scrubber([token], shapes=True)
        # The organisation the projects live under. Needed only by `list_unresolved`, because the
        # detail routes are addressed by issue id and the list route is not — and it cannot be
        # discovered: the least-privilege token this uses is refused `/api/0/organizations/`
        # (measured, 403), which is correct and means an operator has to say it (DR-0011).
        self._organisation = organisation

    def _get(self, path: str) -> Any:  # noqa: ANN401 - provider JSON is arbitrary by nature
        try:
            response = self._client.get(path)
        except httpx2.TimeoutException as exc:
            raise RetryableTrackerError(f"tracker timed out: {exc}") from exc
        except httpx2.HTTPError as exc:
            raise RetryableTrackerError(f"tracker unreachable: {exc}") from exc

        if response.status_code == _NOT_FOUND:
            return None
        if response.status_code in _RETRYABLE_STATUS:
            raise RetryableTrackerError(
                f"tracker returned {response.status_code}", response.status_code
            )
        if response.status_code >= 400:
            raise PermanentTrackerError(
                f"tracker refused the request with {response.status_code}", response.status_code
            )
        try:
            return response.json()
        except ValueError as exc:
            raise PermanentTrackerError(f"tracker sent something that is not JSON: {exc}") from exc

    def _issue_id(self, permalink: str) -> str:
        match = _ISSUE_IN_PERMALINK.search(permalink or "")
        if not match:
            raise PermanentTrackerError(f"no issue id in permalink {permalink!r}")
        return match.group(1)

    def fetch_latest(self, permalink: str) -> FetchedEvent | None:
        payload = self._get(f"/api/0/issues/{self._issue_id(permalink)}/events/latest/")
        return self._build(payload) if isinstance(payload, dict) else None

    def fetch_samples(self, permalink: str, limit: int = 2) -> Sequence[FetchedEvent]:
        """Newest first. Falls back to the single latest event if the route is unavailable."""
        latest = self.fetch_latest(permalink)
        if latest is None or limit <= 1:
            return [latest] if latest else []
        payload = self._get(f"/api/0/issues/{self._issue_id(permalink)}/events/?limit={limit}")
        if not isinstance(payload, list):
            return [latest]
        built = [self._build(item) for item in payload if isinstance(item, dict)]
        return [event for event in built if event is not None] or [latest]

    def list_unresolved(
        self, project: str, *, since: datetime | None = None, limit: int = 25
    ) -> Sequence[TrackerIssue]:
        """`GET /api/0/projects/{org}/{project}/issues/?query=is:unresolved`. DR-0011, item 080.

        **The first list route this adapter touches**, and the module docstring's reason for
        avoiding
        them holds only in part — so both halves are stated here rather than left to contradict each
        other:

        * the broken `Link` header is real and was re-measured on 2026-07-30: it comes back as
          `{'<…>; rel="previous"; results="false", <…>'}`, in Python set syntax. So **this method
          never
          paginates.** It asks for one bounded page and the caller advances `since`.
        * the docstring says list routes answer snake_case. Measured on *this* route: they do
          **not** —
          `firstSeen`, `lastSeen`, `numComments`, `shortId` are all camelCase. The claim was true of
          the event list route and was over-generalised. This parser reads what this route sends.

        Filtered here rather than by asking the provider for a time window, because `query=` syntax
        is
        the part of that API least likely to be stable and a wrong filter silently returns nothing —
        which would look exactly like a clean inventory.
        """
        payload = self._get(
            f"/api/0/projects/{self._organisation}/{project}/issues/?query=is%3Aunresolved"
        )
        if not isinstance(payload, list):
            # `None` is a 404 from `_get`: the project does not exist under this organisation, which
            # is a configuration error and not an empty inventory. Loud, because the two look
            # identical from the outside and only one is fine.
            msg = (
                f"the tracker has no project {self._organisation}/{project!r}, or it answered with "
                f"something other than a list of issues"
            )
            raise PermanentTrackerError(msg)

        issues = [
            built
            for row in payload
            if isinstance(row, Mapping) and (built := self._issue(row)) is not None
        ]
        fresh = [
            issue
            for issue in issues
            if since is None or issue.last_seen is None or issue.last_seen > since
        ]
        # Oldest activity first, so a caller that advances `since` to the last one it handled makes
        # progress instead of re-reading the same newest page for ever.
        fresh.sort(key=lambda issue: (issue.last_seen or _EPOCH, issue.external_id))
        return fresh[:limit]

    def _issue(self, row: Mapping[str, Any]) -> TrackerIssue | None:
        """One list row → `TrackerIssue`. Separate from `_build`, deliberately.

        `_build` parses a detail route's camelCase event with frames and locals; this parses a
        summary
        of an issue. One function for both would have to guess which shape it was handed, and the
        two
        disagree about more than casing — this route has no `entries`, no `eventID`, and carries
        `metadata` that the detail route does not.
        """
        external_id = row.get("id")
        title = row.get("title")
        permalink = row.get("permalink")
        if not external_id or not title or not permalink:
            # Identity or destination missing. Skipped rather than raised: one unusable row must not
            # cost the whole inventory, the same rule `drain_pending` follows for one bad payload.
            log.warning("unusable issue row from the tracker", extra={"keys": sorted(row)})
            return None

        raw_metadata = row.get("metadata")
        metadata: Mapping[str, Any] = (
            raw_metadata if isinstance(raw_metadata, Mapping) else {}
        )
        # `culprit` is `""` on this route where the webhook sent `null`, and the useful location is
        # in
        # `metadata` instead. Measured on the live instance: `filename` and `function` are populated
        # for every real error, which is the half the 437-byte webhook never carried.
        where = ":".join(
            str(part)
            for part in (metadata.get("filename"), metadata.get("function"))
            if part
        )
        culprit = str(row.get("culprit") or "") or where or None

        return TrackerIssue(
            external_id=str(external_id),
            title=str(title),
            permalink=str(permalink),
            status=str(row.get("status") or "unknown"),
            level=str(row["level"]) if row.get("level") else None,
            culprit=culprit,
            # A string on this route — `"58"`, not `58`.
            occurrences=int(row["count"]) if str(row.get("count") or "").isdigit() else None,
            first_seen=_utc(row.get("firstSeen")),
            last_seen=_utc(row.get("lastSeen")),
        )

    def _build(self, payload: Mapping[str, Any]) -> FetchedEvent | None:
        """Turn one provider event into ours, scrubbing everything on the way in.

        Tolerant by design: a missing key means the SDK did not send that thing, never that the
        event is unusable. The list routes' snake_case names are accepted alongside the detail
        routes' camelCase so that a caller who ever does reach for a list does not get silence.
        """
        event_id = str(payload.get("eventID") or payload.get("event_id") or payload.get("id") or "")
        if not event_id:
            return None

        exception = _entry(payload, "exception") or {}
        values = exception.get("values") or []
        first: Mapping[str, Any] = values[0] if values and isinstance(values[0], dict) else {}
        raw_mechanism = first.get("mechanism")
        mechanism: Mapping[str, Any] = raw_mechanism if isinstance(raw_mechanism, dict) else {}

        tags = _tags(payload)
        raw_contexts = payload.get("contexts")
        contexts: Mapping[str, Any] = raw_contexts if isinstance(raw_contexts, dict) else {}
        raw_runtime = contexts.get("runtime")
        runtime: Mapping[str, Any] = raw_runtime if isinstance(raw_runtime, dict) else {}

        raw_packages = payload.get("packages")
        packages = (
            {str(name): str(version) for name, version in raw_packages.items()}
            if isinstance(raw_packages, dict)
            else {}
        )

        message = first.get("value")
        if message is None:
            metadata = payload.get("metadata")
            message = metadata.get("value") if isinstance(metadata, dict) else None

        return FetchedEvent(
            provider_event_id=event_id,
            exception_type=first.get("type") or None,
            message=self._scrub.text(str(message)) if message is not None else None,
            culprit=payload.get("culprit") or None,
            handled=mechanism.get("handled"),
            # `level` is a string on the raw route and absent from this one; the tag carries it.
            level=payload.get("level") or tags.get("level") or None,
            frames=self._frames(first),
            packages=packages,
            runtime=f"{runtime.get('name')} {runtime.get('version')}".strip()
            if runtime.get("name")
            else None,
            environment=tags.get("environment"),
            release=tags.get("release"),
            server_name=tags.get("server_name"),
            occurred_at=_utc(payload.get("dateCreated") or payload.get("date_created")),
            grouping_hashes=tuple(str(h) for h in (payload.get("hashes") or [])),
            extra=self._scrub.scrub(payload.get("extra") or {}),
        )

    def _frames(self, exception_value: Mapping[str, Any]) -> tuple[Frame, ...]:
        stacktrace = exception_value.get("stacktrace")
        if not isinstance(stacktrace, dict):
            return ()
        raw_frames = [f for f in (stacktrace.get("frames") or []) if isinstance(f, dict)]
        # Keep the innermost frames: the tail is where the error happened, the head is the runner.
        return tuple(self._frame(f) for f in raw_frames[-MAX_FRAMES:])

    def _frame(self, raw: Mapping[str, Any]) -> Frame:
        context: list[tuple[int, str]] = []
        for pair in raw.get("context") or []:
            if isinstance(pair, list | tuple) and len(pair) == _PAIR:
                try:
                    context.append((int(pair[0]), self._scrub.text(str(pair[1]))))
                except (TypeError, ValueError):
                    continue

        variables = raw.get("vars")
        scrubbed: dict[str, Any] | None = None
        if isinstance(variables, dict):
            # Scrub the mapping **as a mapping**, in one call. Walking it here and scrubbing each
            # value separately looked equivalent and was not: the by-name defence only fires when
            # the scrubber is the one holding the keys, so `password` came through untouched. The
            # most valuable of the three defences, silently skipped on the most sensitive field —
            # found by a test, which is the only reason it is not in the database.
            walked = self._scrub.scrub(variables)
            scrubbed = {
                str(name): self._truncate(value) for name, value in walked.items()
            }

        line = raw.get("lineNo", raw.get("lineno"))
        return Frame(
            filename=raw.get("filename") or None,
            abs_path=raw.get("absPath") or raw.get("abs_path") or None,
            module=raw.get("module") or None,
            function=raw.get("function") or None,
            lineno=int(line) if isinstance(line, int) else None,
            context_line=self._scrub.text(str(raw["context_line"]))
            if raw.get("context_line") is not None
            else None,
            context=tuple(context),
            variables=scrubbed,
        )

    @staticmethod
    def _truncate(value: Any) -> Any:  # noqa: ANN401 - locals are arbitrary by nature
        text = value if isinstance(value, str) else repr(value)
        if len(text) <= MAX_VAR_CHARS:
            return value
        return f"{text[:MAX_VAR_CHARS]}… [{len(text) - MAX_VAR_CHARS} more characters]"

    def close(self) -> None:
        self._client.close()
