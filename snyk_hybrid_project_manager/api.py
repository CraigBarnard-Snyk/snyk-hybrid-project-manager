"""Thin Snyk REST API client with pagination and retry handling."""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import urljoin

import requests

from . import __version__

JSON_API_CONTENT_TYPE = "application/vnd.api+json"
RETRIABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_BULK_DELETE = 100
PAGE_LIMIT = 100
MAX_BACKOFF_SECONDS = 60.0
MAX_RETRY_AFTER_SECONDS = 300.0

log = logging.getLogger(__name__)


class SnykApiError(Exception):
    """A non-retriable API failure, or a retriable one that exhausted retries."""

    def __init__(self, message: str, status: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status = status
        self.body = body


class SnykClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        api_version: str,
        auth_scheme: str = "token",
        timeout: float = 60.0,
        max_retries: int = 5,
        session: requests.Session | None = None,
        sleep=time.sleep,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_version = api_version
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleep = sleep
        self.session = session or requests.Session()
        prefix = "Bearer" if auth_scheme == "bearer" else "token"
        self.session.headers.update(
            {
                "Authorization": f"{prefix} {token}",
                "Accept": JSON_API_CONTENT_TYPE,
                "User-Agent": f"snyk-hybrid-project-manager/{__version__}",
            }
        )

    # -- plumbing ---------------------------------------------------------

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/rest/"):
            path = "/rest/" + path.lstrip("/")
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                pass
        base = min(2.0**attempt, MAX_BACKOFF_SECONDS)
        return base * (0.5 + random.random() / 2)

    def _request(
        self,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Issue a request, retrying 429/5xx and transport errors with backoff.

        Retrying POST bulk-delete is safe: the endpoint ignores project ids that
        no longer exist in the org, so a replayed batch is a no-op.
        """
        url = self._url(path)
        headers = {"Content-Type": JSON_API_CONTENT_TYPE} if json_body is not None else {}
        last_error: str = ""

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt == self.max_retries - 1:
                    break
                delay = self._backoff(attempt, None)
                log.warning(
                    "%s %s failed (%s); retrying in %.1fs (attempt %d/%d)",
                    method,
                    url,
                    last_error,
                    delay,
                    attempt + 1,
                    self.max_retries,
                )
                self._sleep(delay)
                continue

            if response.status_code in RETRIABLE_STATUS:
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                if attempt == self.max_retries - 1:
                    break
                delay = self._backoff(attempt, response.headers.get("Retry-After"))
                log.warning(
                    "%s %s returned %d; retrying in %.1fs (attempt %d/%d)",
                    method,
                    url,
                    response.status_code,
                    delay,
                    attempt + 1,
                    self.max_retries,
                )
                self._sleep(delay)
                continue

            if response.status_code >= 400:
                raise SnykApiError(
                    f"{method} {url} failed with HTTP {response.status_code}",
                    status=response.status_code,
                    body=response.text[:2000],
                )

            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError as exc:
                raise SnykApiError(
                    f"{method} {url} returned a non-JSON body: {exc}",
                    status=response.status_code,
                    body=response.text[:2000],
                ) from exc

        raise SnykApiError(
            f"{method} {url} failed after {self.max_retries} attempts ({last_error})"
        )

    def _paginate(self, path: str, params: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        """Walk a JSON:API collection via ``links.next``."""
        next_path: str | None = path
        next_params: Mapping[str, Any] | None = {**params, "version": self.api_version}
        seen_cursors: set[str] = set()

        while next_path:
            payload = self._request("GET", next_path, params=next_params)
            for item in payload.get("data") or []:
                yield item

            links = payload.get("links") or {}
            nxt = links.get("next")
            if isinstance(nxt, Mapping):
                nxt = nxt.get("href")
            if not nxt or not isinstance(nxt, str):
                return
            if nxt in seen_cursors:
                log.warning("pagination cursor repeated for %s; stopping", path)
                return
            seen_cursors.add(nxt)
            # The next link already carries version and cursor.
            next_path, next_params = nxt, None

    # -- endpoints --------------------------------------------------------

    def list_group_orgs(self, group_id: str) -> list[dict[str, Any]]:
        """GET /rest/groups/{group_id}/orgs"""
        return list(self._paginate(f"/groups/{group_id}/orgs", {"limit": PAGE_LIMIT}))

    def get_org(self, org_id: str) -> dict[str, Any]:
        """GET /rest/orgs/{org_id}"""
        payload = self._request("GET", f"/orgs/{org_id}", params={"version": self.api_version})
        return payload.get("data") or {}

    def list_projects(self, org_id: str) -> Iterator[dict[str, Any]]:
        """GET /rest/orgs/{org_id}/projects with the target relationship expanded.

        ``expand=target`` is what puts the repo URL on each project at
        ``relationships.target.data.attributes.url``; without it every project
        would look like it had no repo URL.
        """
        yield from self._paginate(
            f"/orgs/{org_id}/projects",
            {"limit": PAGE_LIMIT, "expand": "target"},
        )

    def bulk_delete_projects(
        self,
        org_id: str,
        project_ids: Sequence[str],
        exclude_from_future_scans: bool,
    ) -> dict[str, list[dict[str, Any]]]:
        """POST /rest/orgs/{org_id}/projects/bulk-delete for up to 100 projects.

        A partially successful request still returns 200, so both ``deleted``
        and ``failed`` must be read from ``meta``.
        """
        if not project_ids:
            return {"deleted": [], "failed": []}
        if len(project_ids) > MAX_BULK_DELETE:
            raise ValueError(
                f"bulk delete accepts at most {MAX_BULK_DELETE} projects, got {len(project_ids)}"
            )

        body = {
            "data": [{"type": "project", "id": pid} for pid in project_ids],
            "meta": {"exclude_from_future_scans": exclude_from_future_scans},
        }
        payload = self._request(
            "POST",
            f"/orgs/{org_id}/projects/bulk-delete",
            params={"version": self.api_version},
            json_body=body,
        )
        meta = payload.get("meta") or {}
        return {
            "deleted": list(meta.get("deleted") or []),
            "failed": list(meta.get("failed") or []),
        }


def chunked(items: Sequence[Any], size: int = MAX_BULK_DELETE) -> Iterator[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]
