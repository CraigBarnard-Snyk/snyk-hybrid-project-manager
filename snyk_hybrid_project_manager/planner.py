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

# Stand-ins for a repo URL in records that are not keyed on one.
ORG_WIDE = "<entire org>"
NO_REPO_URL = "<no repo url>"


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

        Only active projects count on either side: deleting an inactive project
        loses no coverage, and an inactive one provides none.
        """
        return self.active_delete_count > self.active_keep_count

    @property
    def active_delete_count(self) -> int:
        return sum(1 for p in self.to_delete if p.is_active)

    @property
    def active_keep_count(self) -> int:
        return sum(1 for p in self.to_keep if p.is_active)


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

    def inactive_delete_count(self) -> int:
        """Of the projects this run would remove, how many are already dead."""
        return sum(1 for _, p in self.projects_to_delete() if not p.is_active)

    def skip_counts(self) -> Counter:
        return Counter(s.reason for s in self.skips)

    def unmatched_counts(self) -> Counter:
        """Repos with only one side, by side."""
        return Counter(u.side for u in self.unmatched)


def _inactive_is_deletable(project: Project, side: str, config: Config) -> bool:
    """An inactive project may be deleted when opted in, but is never kept.

    Keeping a dead project in place of a live one would leave the repo
    unmonitored, so an inactive project on the side being kept is always
    skipped. Only an explicitly inactive status qualifies: a missing or
    unrecognised one is not evidence of anything.
    """
    return config.delete_inactive and project.is_inactive and side == config.delete


def _default_branch_by_repo(
    scm_projects: Sequence[tuple[Project, str]],
    preferred: Sequence[str],
) -> dict[str, str]:
    """Choose one default branch per repo from the SCM projects present."""
    by_repo: dict[str, dict[str, list[Project]]] = defaultdict(lambda: defaultdict(list))
    for project, repo in scm_projects:
        # An inactive project should not tip the "busiest branch" heuristic.
        if project.is_active:
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

        # Cheap gate first so the default path is untouched: with the opt-in
        # off, an inactive project never reaches classification, and still
        # reports `inactive` rather than whatever it would fail next.
        if not project.is_active and not config.delete_inactive:
            plan.skips.append(Skip(project, SKIP_INACTIVE, project.status))
            continue

        side = classify_origin(project.origin, CLI_ORIGINS, SCM_ORIGINS)
        if side is None:
            plan.skips.append(Skip(project, SKIP_UNCLASSIFIED_ORIGIN, project.origin))
            continue

        if not project.is_active and not _inactive_is_deletable(project, side, config):
            plan.skips.append(Skip(project, SKIP_INACTIVE, project.status))
            continue

        repo = canonical_repo_url(project.target_url)
        if not repo and config.match_level == "repo":
            # Repo matching has nothing to match on without a URL. Org matching
            # does not need one, so there it is not a reason to skip.
            plan.skips.append(
                Skip(project, SKIP_NO_REPO_URL, project.target_display_name or "")
            )
            continue

        classified.append((project, side, repo))

    default_branches: dict[str, str] = {}
    if config.branch_match == "scm_default":
        default_branches = _default_branch_by_repo(
            [(p, repo) for p, side, repo in classified if side == SCM and repo],
            config.default_branches,
        )

    eligible: list[tuple[Project, str, str | None]] = []
    for project, side, repo in classified:
        if config.branch_match == "scm_default" and side == SCM and repo:
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
        eligible.append((project, side, repo))

    if config.match_level == "org":
        _plan_org_level(plan, eligible, config)
    else:
        _plan_repo_level(plan, eligible, config)

    if (
        config.max_deletes_per_org is not None
        and plan.delete_count > config.max_deletes_per_org
    ):
        plan.capped = True

    return plan


def _by_repo(
    eligible: Sequence[tuple[Project, str, str | None]],
) -> dict[str, dict[str, list[Project]]]:
    grouped: dict[str, dict[str, list[Project]]] = defaultdict(lambda: {CLI: [], SCM: []})
    for project, side, repo in eligible:
        grouped[repo or NO_REPO_URL][side].append(project)
    return grouped


def _sorted(projects: Iterable[Project]) -> tuple[Project, ...]:
    return tuple(sorted(projects, key=lambda p: (p.created, p.id)))


def _plan_repo_level(
    plan: OrgPlan,
    eligible: Sequence[tuple[Project, str, str | None]],
    config: Config,
) -> None:
    """Default matching: a repo must be covered by both sides to be a duplicate."""
    grouped = _by_repo(eligible)
    for repo in sorted(grouped):
        sides = grouped[repo]
        if sides[CLI] and sides[SCM]:
            plan.duplicates.append(
                Duplicate(
                    repo=repo,
                    cli=_sorted(sides[CLI]),
                    scm=_sorted(sides[SCM]),
                    delete_side=config.delete,
                )
            )
            continue
        for side in (CLI, SCM):
            if sides[side]:
                plan.unmatched.append(
                    Unmatched(repo=repo, side=side, projects=_sorted(sides[side]))
                )


def _plan_org_level(
    plan: OrgPlan,
    eligible: Sequence[tuple[Project, str, str | None]],
    config: Config,
) -> None:
    """Loose matching: one project on the keeping side condemns the whole other side.

    Repo URLs are not compared at all. If the org has even one Open Source
    project on the side being kept, every Open Source project on the side being
    deleted goes, whatever repo it belongs to.
    """
    by_side: dict[str, list[Project]] = {CLI: [], SCM: []}
    for project, side, _ in eligible:
        by_side[side].append(project)

    keep_side = CLI if config.delete == SCM else SCM
    if by_side[keep_side] and by_side[config.delete]:
        plan.duplicates.append(
            Duplicate(
                repo=ORG_WIDE,
                cli=_sorted(by_side[CLI]),
                scm=_sorted(by_side[SCM]),
                delete_side=config.delete,
            )
        )
        return

    # The org has only one side, so nothing is condemned. Record what is there.
    grouped = _by_repo(eligible)
    for repo in sorted(grouped):
        for side in (CLI, SCM):
            if grouped[repo][side]:
                plan.unmatched.append(
                    Unmatched(repo=repo, side=side, projects=_sorted(grouped[repo][side]))
                )


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
        "canonical_repo_url": repo if repo is not None else canonical_repo_url(project.target_url),
        "manifest_path": project_path(project),
    }
