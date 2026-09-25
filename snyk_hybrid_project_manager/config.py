"""Configuration loading and validation.

The config file carries the decisions a run cannot make for itself: which side
to delete, and which orgs to look at. Everything else is a constant below.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

# The bulk-delete endpoint first appears in the 2024-10-15 GA version of the
# Snyk REST API. Anything older will 404, so refuse to start.
MIN_API_VERSION = "2024-10-15"
DEFAULT_API_VERSION = "2026-03-25"
DEFAULT_API_URL = "https://api.snyk.io"

DELETE_SIDES = ("scm", "cli")
BRANCH_MATCH_MODES = ("ignore", "scm_default")
AUTH_SCHEMES = ("token", "bearer")

DEFAULT_BRANCHES = ("main", "master")

REQUEST_TIMEOUT = 60.0
MAX_RETRIES = 5

CLI_ORIGINS = frozenset({"cli"})

SCM_ORIGINS = frozenset(
    {
        "github",
        "github-enterprise",
        "github-cloud-app",
        "gitlab",
        "gitlab-enterprise",
        "gitlab-cloud-app",
        "bitbucket-cloud",
        "bitbucket-cloud-app",
        "bitbucket-server",
        "bitbucket-connect-app",
        "bitbucket-data-center",
        "azure-repos",
    }
)

# An allowlist: only these types may be deleted. Anything else -- Snyk Code,
# Container, IaC, and any product Snyk ships in future -- is skipped and
# recorded in the run log's type census, so an omission here costs a missed
# duplicate rather than a wrong deletion.
OSS_TYPES = frozenset(
    {
        # JavaScript
        "npm",
        "yarn",
        "yarn-workspace",
        "pnpm",
        # JVM
        "maven",
        "gradle",
        "sbt",
        # Python
        "pip",
        "poetry",
        "pipenv",
        # .NET
        "nuget",
        "paket",
        # PHP
        "composer",
        # Ruby
        "rubygems",
        # Go
        "gomodules",
        "golang",
        "golangdep",
        "govendor",
        # Swift / Objective-C
        "cocoapods",
        "swift",
        "swiftpm",
        # Others
        "hex",
        "cargo",
        "cpp",
        "conan",
    }
)


class ConfigError(Exception):
    """Raised when the config file is missing, malformed, or contradictory."""


@dataclass
class Config:
    """Effective settings for a run. One set of settings applies to every org."""

    delete: str = "scm"
    orgs: tuple[str, ...] = ()
    group_id: str | None = None
    exclude_orgs: tuple[str, ...] = ()
    api_url: str = DEFAULT_API_URL
    api_version: str = DEFAULT_API_VERSION
    auth_scheme: str = "token"
    branch_match: str = "ignore"
    default_branches: tuple[str, ...] = DEFAULT_BRANCHES
    max_deletes_per_org: int | None = None
    log_dir: str = "./logs"
    # Not a config key; set only by --no-exclude-from-future-scans. Always on
    # for SCM deletions, because a deleted SCM project that isn't excluded is
    # recreated by the next sync.
    exclude_from_future_scans: bool = True

    def is_excluded(self, org_id: str, name: str | None, slug: str | None) -> bool:
        """Exclusions may be given as an org id, a slug, or a display name."""
        candidates = {c.lower() for c in (org_id, name, slug) if c}
        return any(x.lower() in candidates for x in self.exclude_orgs)


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ConfigError(f"{where} must be a list of strings")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{where} must contain only strings, got {item!r}")
        out.append(item.strip())
    return tuple(x for x in out if x)


def _one_of(value: Any, allowed: tuple[str, ...], where: str) -> str:
    if not isinstance(value, str) or value.lower() not in allowed:
        raise ConfigError(f"{where} must be one of {', '.join(allowed)}, got {value!r}")
    return value.lower()


def _positive_int(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{where} must be a positive integer, got {value!r}")
    return value


def _version_date(version: str) -> str:
    """Strip a ``~beta``/``~experimental`` suffix, leaving the ISO date."""
    return version.split("~", 1)[0]


def _org_ids(value: Any) -> tuple[str, ...]:
    """``orgs`` is a plain list of org ids."""
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ConfigError("orgs must be a list of org ids")

    ids: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(value):
        if isinstance(entry, Mapping):
            raise ConfigError(
                f"orgs[{index}] must be an org id string. One set of settings applies to "
                "every org; run the tool once per group of orgs that need different settings."
            )
        if not isinstance(entry, str) or not entry.strip():
            raise ConfigError(f"orgs[{index}] must be a non-empty org id string")
        org_id = entry.strip()
        if org_id.lower() in seen:
            raise ConfigError(f"org {org_id} is listed more than once under orgs")
        seen.add(org_id.lower())
        ids.append(org_id)
    return tuple(ids)


def load_config(path: str | os.PathLike[str]) -> Config:
    """Read and validate the YAML config file."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse {config_path}: {exc}") from exc

    data = _require_mapping(raw, "config file")

    known = {
        "delete",
        "orgs",
        "group",
        "api_url",
        "api_version",
        "auth_scheme",
        "branch_match",
        "default_branches",
        "max_deletes_per_org",
        "log_dir",
    }
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")

    group = _require_mapping(data.get("group"), "group")
    group_unknown = set(group) - {"id", "exclude_orgs"}
    if group_unknown:
        raise ConfigError(f"unknown keys under group: {', '.join(sorted(group_unknown))}")

    group_id = group.get("id")
    if group_id is not None and (not isinstance(group_id, str) or not group_id.strip()):
        raise ConfigError("group.id must be a non-empty string")
    group_id = group_id.strip() if isinstance(group_id, str) else None

    orgs = _org_ids(data.get("orgs"))
    if not group_id and not orgs:
        raise ConfigError("config must define either group.id or a non-empty orgs list")

    api_version = data.get("api_version", DEFAULT_API_VERSION)
    if not isinstance(api_version, str) or not api_version.strip():
        raise ConfigError("api_version must be a non-empty string")
    api_version = api_version.strip()
    if _version_date(api_version) < MIN_API_VERSION:
        raise ConfigError(
            f"api_version {api_version} predates {MIN_API_VERSION}, the first version that "
            "supports POST /orgs/{org_id}/projects/bulk-delete"
        )

    api_url = data.get("api_url", DEFAULT_API_URL)
    if not isinstance(api_url, str) or not api_url.strip():
        raise ConfigError("api_url must be a non-empty string")

    default_branches = data.get("default_branches")

    return Config(
        delete=_one_of(data.get("delete", "scm"), DELETE_SIDES, "delete"),
        orgs=orgs,
        group_id=group_id,
        exclude_orgs=_str_tuple(group.get("exclude_orgs"), "group.exclude_orgs"),
        api_url=api_url.strip().rstrip("/"),
        api_version=api_version,
        auth_scheme=_one_of(data.get("auth_scheme", "token"), AUTH_SCHEMES, "auth_scheme"),
        branch_match=_one_of(
            data.get("branch_match", "ignore"), BRANCH_MATCH_MODES, "branch_match"
        ),
        default_branches=(
            _str_tuple(default_branches, "default_branches")
            if default_branches is not None
            else DEFAULT_BRANCHES
        ),
        max_deletes_per_org=_positive_int(data.get("max_deletes_per_org"), "max_deletes_per_org"),
        log_dir=str(data.get("log_dir") or "./logs"),
    )


def read_token(env: Mapping[str, str] | None = None) -> str:
    """The API token is only ever read from the environment, never the config file."""
    env = os.environ if env is None else env
    token = (env.get("SNYK_TOKEN") or "").strip()
    if not token:
        raise ConfigError(
            "SNYK_TOKEN is not set. Export a Snyk service account token with the "
            "'View Projects' (org.project.read) and 'Remove Projects' (org.project.delete) "
            "permissions before running."
        )
    return token
