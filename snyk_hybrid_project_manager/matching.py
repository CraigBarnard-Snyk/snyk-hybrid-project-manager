"""Repo URL normalisation and project classification. Performs no I/O.

Projects are matched at the *repository* level: if a repo has Open Source
projects from both the CLI and an SCM integration, one side is redundant. The
manifest path plays no part, so ``package.json`` and ``frontend/package.json``
are not lined up against each other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

CLI = "cli"
SCM = "scm"

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_SCP_RE = re.compile(r"^(?P<user>[^@/]+@)?(?P<host>[^:/]+):(?P<path>.+)$")
_PORT_RE = re.compile(r":\d+$")


def canonical_repo_url(url: str | None) -> str | None:
    """Reduce any remote URL form to ``host/owner/repo``, or ``None``.

    The CLI takes the repo URL from ``git remote``, so it usually carries the
    SSH form (``git@github.com:acme/api.git``) while the SCM integration
    carries the HTTPS form (``https://github.com/acme/api``). Both must reduce
    to ``github.com/acme/api`` or nothing will match.
    """
    if not url:
        return None

    value = url.strip()
    if not value:
        return None

    # scp-style syntax (git@host:owner/repo) has no scheme and cannot be parsed
    # by urlsplit, so normalise it to host/path first.
    if not _SCHEME_RE.match(value):
        match = _SCP_RE.match(value)
        if match:
            value = f"{match.group('host')}/{match.group('path')}"
        # else: assume it is already bare (host/owner/repo)
    else:
        value = _SCHEME_RE.sub("", value, count=1)

    # Strip any userinfo (git@, user:token@) from the authority.
    if "@" in value.split("/", 1)[0]:
        value = value.split("@", 1)[1]

    value = value.strip("/")
    if not value:
        return None

    parts = value.split("/", 1)
    host = _PORT_RE.sub("", parts[0]).lower()
    path = parts[1] if len(parts) > 1 else ""

    # ssh.dev.azure.com and ssh.github.com alias the host the SCM side records.
    if host.startswith("ssh."):
        host = host[len("ssh.") :]

    path = path.strip("/")
    if path.lower().endswith(".git"):
        path = path[: -len(".git")]

    # Bitbucket Server and Azure DevOps insert routing segments that are absent
    # from the browser URL the SCM integration records.
    segments = [s for s in path.split("/") if s]
    # Azure DevOps SSH remotes are git@ssh.dev.azure.com:v3/org/project/repo.
    if segments and segments[0].lower() == "v3" and ("azure" in host or "visualstudio" in host):
        segments = segments[1:]
    if segments and segments[0].lower() in {"scm", "_git"}:
        segments = segments[1:]
    segments = [s for s in segments if s.lower() != "_git"]

    path = "/".join(segments).lower()
    if not path:
        return None
    return f"{host}/{path}"


def normalise_path(target_file: str | None) -> str:
    """Normalise a manifest path so CLI and SCM spellings line up.

    Case is preserved: manifest paths are case-sensitive on the Linux hosts
    that do the scanning.
    """
    if not target_file:
        return ""
    value = target_file.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = re.sub(r"/{2,}", "/", value)
    return value.strip("/")


def normalise_branch(target_reference: str | None) -> str:
    if not target_reference:
        return ""
    return target_reference.strip().lower()


def classify_origin(
    origin: str | None,
    cli_origins: Iterable[str],
    scm_origins: Iterable[str],
) -> str | None:
    """Return ``"cli"``, ``"scm"``, or ``None`` when the origin is unclassified.

    ``None`` covers origins such as ``api`` whose provenance is genuinely
    ambiguous -- those projects are skipped rather than guessed at.
    """
    if not origin:
        return None
    value = origin.strip().lower()
    if value in {o.lower() for o in cli_origins}:
        return CLI
    if value in {o.lower() for o in scm_origins}:
        return SCM
    return None


@dataclass(frozen=True)
class Project:
    """The subset of a REST project payload this tool reasons about."""

    id: str
    name: str
    origin: str
    type: str
    target_file: str
    target_reference: str
    status: str
    created: str
    target_id: str | None
    target_url: str | None
    target_display_name: str | None

    @property
    def is_active(self) -> bool:
        return self.status.lower() == "active"


def _target_relationship(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    rel = (payload.get("relationships") or {}).get("target") or {}
    data = rel.get("data")
    return data if isinstance(data, Mapping) else {}


def parse_project(payload: Mapping[str, Any]) -> Project:
    """Build a :class:`Project` from one ``data[i]`` entry of the REST response.

    Assumes the request was made with ``expand=target`` so that the repo URL is
    present at ``relationships.target.data.attributes.url``.
    """
    attrs = payload.get("attributes") or {}
    target = _target_relationship(payload)
    target_attrs = target.get("attributes") or {}
    return Project(
        id=str(payload.get("id") or ""),
        name=str(attrs.get("name") or ""),
        origin=str(attrs.get("origin") or ""),
        type=str(attrs.get("type") or ""),
        target_file=str(attrs.get("target_file") or ""),
        target_reference=str(attrs.get("target_reference") or ""),
        status=str(attrs.get("status") or ""),
        created=str(attrs.get("created") or ""),
        target_id=str(target.get("id")) if target.get("id") else None,
        target_url=(target_attrs.get("url") or None),
        target_display_name=(target_attrs.get("display_name") or None),
    )


def project_path(project: Project) -> str:
    """The manifest path, preferring ``target_file``.

    SCM project *names* are ``owner/repo:path/to/pom.xml``; the path after the
    colon is used only as a fallback for the rare payload with an empty
    ``target_file``.
    """
    path = normalise_path(project.target_file)
    if path:
        return path
    if ":" in project.name:
        return normalise_path(project.name.split(":", 1)[1])
    return ""


def select_default_branch(
    branches: Sequence[tuple[str, int, str]],
    preferred: Sequence[str] = ("main", "master"),
) -> str | None:
    """Pick a repo's default branch from its SCM target references.

    The REST API does not expose a target's default branch, so this is a
    documented heuristic over ``(branch, project_count, earliest_created)``:

    1. the first ``preferred`` branch name present, else
    2. the branch carrying the most projects, ties broken by the earliest
       created project, then by name for determinism.
    """
    if not branches:
        return None
    available = {b.lower(): b for b, _, _ in branches}
    for name in preferred:
        if name.lower() in available:
            return available[name.lower()]
    return sorted(branches, key=lambda item: (-item[1], item[2], item[0]))[0][0]
