"""Turn a list of projects into a deletion plan. Read-only; performs no I/O."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .config import CLI_ORIGINS, OSS_TYPES, SCM_ORIGINS, Config
from .matching import (
    CLI,
    SCM,
    Project,
    canonical_repo_url,
    classify_origin,
    normalise_branch,
    project_path,
    select_default_branch,
)

SKIP_NON_OSS_TYPE = "non_oss_type"
SKIP_INACTIVE = "inactive"
SKIP_UNCLASSIFIED_ORIGIN = "origin_not_classified"
SKIP_NO_REPO_URL = "no_repo_url"
SKIP_NON_DEFAULT_BRANCH = "non_default_branch"


@dataclass(frozen=True)
class Org:
    id: str
    name: str | None = None
    slug: str | None = None

    @property
    def label(self) -> str:
        return f"{self.name or self.slug or self.id} ({self.id})"


@dataclass(frozen=True)
class Skip:
    project: Project
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class Unmatched:
    """A repo monitored from one side only, so there is nothing to remove.

    Recorded per repo rather than per project to keep the log readable.
    """

    repo: str
    side: str
    projects: tuple[Project, ...]


@dataclass
class Duplicate:
    """A repo monitored by both the CLI and an SCM integration.

    Every Open Source project on the losing side is removed; the two sides are
    not lined up manifest by manifest.
    """

    repo: str
    cli: tuple[Project, ...]
    scm: tuple[Project, ...]
    delete_side: str
    skipped_by_review: bool = False

    @property
    def to_delete(self) -> tuple[Project, ...]:
        return self.cli if self.delete_side == CLI else self.scm

    @property
    def to_keep(self) -> tuple[Project, ...]:
        return self.scm if self.delete_side == CLI else self.cli

    @property
    def coverage_drop(self) -> bool:
        """True when the losing side covers more manifests than the winner.

        Deleting the SCM side of a repo whose CI only ever scanned one manifest
        leaves the rest unmonitored. Reported, not blocked.
        """
        return len(self.to_delete) > len(self.to_keep)


@dataclass
class OrgPlan:
    org: Org
    config: Config
    duplicates: list[Duplicate] = field(default_factory=list)
    skips: list[Skip] = field(default_factory=list)
    unmatched: list[Unmatched] = field(default_factory=list)
    total_projects: int = 0
    oss_projects: int = 0
    type_census: Counter = field(default_factory=Counter)
    capped: bool = False

    @property
    def active_duplicates(self) -> list[Duplicate]:
        return [d for d in self.duplicates if not d.skipped_by_review]

    @property
    def delete_count(self) -> int:
        """Projects this run would actually remove."""
        return sum(len(d.to_delete) for d in self.active_duplicates)

    @property
    def coverage_drops(self) -> list[Duplicate]:
        return [d for d in self.duplicates if d.coverage_drop]

    @property
    def duplicate_project_count(self) -> int:
        """Projects identified as the redundant copy, review skips included."""
        return sum(len(d.to_delete) for d in self.duplicates)

    def projects_to_delete(self) -> list[tuple[Duplicate, Project]]:
        return [(d, p) for d in self.active_duplicates for p in d.to_delete]

    def skip_counts(self) -> Counter:
        return Counter(s.reason for s in self.skips)

    def unmatched_counts(self) -> Counter:
        """Repos with only one side, by side."""
        return Counter(u.side for u in self.unmatched)


def _default_branch_by_repo(
    scm_projects: Sequence[tuple[Project, str]],
    preferred: Sequence[str],
) -> dict[str, str]:
    """Choose one default branch per repo from the SCM projects present."""
    by_repo: dict[str, dict[str, list[Project]]] = defaultdict(lambda: defaultdict(list))
    for project, repo in scm_projects:
        by_repo[repo][normalise_branch(project.target_reference)].append(project)

    chosen: dict[str, str] = {}
    for repo, branches in by_repo.items():
        candidates = [
            (branch, len(projects), min((p.created for p in projects), default=""))
            for branch, projects in branches.items()
        ]
        selected = select_default_branch(candidates, preferred)
        if selected is not None:
            chosen[repo] = selected
    return chosen


def build_plan(org: Org, projects: Iterable[Project], config: Config) -> OrgPlan:
    """Classify every project, then find repos covered by both the CLI and SCM."""
    plan = OrgPlan(org=org, config=config)

    classified: list[tuple[Project, str, str]] = []  # (project, side, repo)

    for project in projects:
        plan.total_projects += 1
        project_type = project.type.lower()
        plan.type_census[project_type or "<unknown>"] += 1

        # An unrecognised type is skipped, never assumed to be Open Source. It
        # still lands in the type census so a newly supported package manager
        # shows up in the report.
        if project_type not in OSS_TYPES:
            plan.skips.append(Skip(project, SKIP_NON_OSS_TYPE, project.type))
            continue

        plan.oss_projects += 1

        if not project.is_active:
            plan.skips.append(Skip(project, SKIP_INACTIVE, project.status))
            continue

        side = classify_origin(project.origin, CLI_ORIGINS, SCM_ORIGINS)
        if side is None:
            plan.skips.append(Skip(project, SKIP_UNCLASSIFIED_ORIGIN, project.origin))
            continue

        repo = canonical_repo_url(project.target_url)
        if not repo:
            plan.skips.append(
                Skip(project, SKIP_NO_REPO_URL, project.target_display_name or "")
            )
            continue

        classified.append((project, side, repo))

    default_branches: dict[str, str] = {}
    if config.branch_match == "scm_default":
        default_branches = _default_branch_by_repo(
            [(p, repo) for p, side, repo in classified if side == SCM],
            config.default_branches,
        )

    by_repo: dict[str, dict[str, list[Project]]] = defaultdict(lambda: {CLI: [], SCM: []})

    for project, side, repo in classified:
        if config.branch_match == "scm_default" and side == SCM:
            expected = default_branches.get(repo)
            if expected is not None and normalise_branch(project.target_reference) != expected:
                plan.skips.append(
                    Skip(
                        project,
                        SKIP_NON_DEFAULT_BRANCH,
                        f"{project.target_reference or '<none>'} != {expected}",
                    )
                )
                continue
        by_repo[repo][side].append(project)

    for repo in sorted(by_repo):
        sides = by_repo[repo]
        if sides[CLI] and sides[SCM]:
            plan.duplicates.append(
                Duplicate(
                    repo=repo,
                    cli=tuple(sorted(sides[CLI], key=lambda p: (p.created, p.id))),
                    scm=tuple(sorted(sides[SCM], key=lambda p: (p.created, p.id))),
                    delete_side=config.delete,
                )
            )
            continue
        for side in (CLI, SCM):
            if sides[side]:
                plan.unmatched.append(
                    Unmatched(
                        repo=repo,
                        side=side,
                        projects=tuple(sorted(sides[side], key=lambda p: (p.created, p.id))),
                    )
                )

    if (
        config.max_deletes_per_org is not None
        and plan.delete_count > config.max_deletes_per_org
    ):
        plan.capped = True

    return plan


def describe_project(project: Project, repo: str | None = None) -> dict[str, object]:
    """Flatten a project into the shape written to the JSONL log."""
    return {
        "id": project.id,
        "name": project.name,
        "origin": project.origin,
        "type": project.type,
        "target_file": project.target_file,
        "target_reference": project.target_reference,
        "status": project.status,
        "created": project.created,
        "target_id": project.target_id,
        "target_url": project.target_url,
        "canonical_repo_url": repo,
        "manifest_path": project_path(project),
    }
