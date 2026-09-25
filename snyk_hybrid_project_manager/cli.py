"""Command line entry point and run orchestration."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from typing import Sequence

from . import __version__
from .api import MAX_BULK_DELETE, SnykApiError, SnykClient, chunked
from .config import (
    BRANCH_MATCH_MODES,
    DELETE_SIDES,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    Config,
    ConfigError,
    load_config,
    read_token,
)
from .matching import CLI, SCM, parse_project
from .planner import (
    SKIP_NON_DEFAULT_BRANCH,
    SKIP_NO_REPO_URL,
    SKIP_UNCLASSIFIED_ORIGIN,
    Duplicate,
    Org,
    OrgPlan,
    build_plan,
    describe_project,
)
from .reporting import Reporter

EXIT_OK = 0
EXIT_PARTIAL_FAILURE = 1
EXIT_CONFIG_ERROR = 2
EXIT_FATAL = 3

# Skip reasons worth a line each in the JSONL log; the rest are summarised as
# counts so a run over thousands of Code/IaC projects stays readable.
TRIAGE_SKIP_REASONS = frozenset(
    {SKIP_NO_REPO_URL, SKIP_UNCLASSIFIED_ORIGIN, SKIP_NON_DEFAULT_BRANCH}
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snyk-hybrid-project-manager",
        description=(
            "Find Snyk Open Source projects imported via both the CLI and an SCM "
            "integration, and delete one side. Dry run unless --execute is given."
        ),
    )
    parser.add_argument("--config", required=True, help="path to the YAML config file")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--execute",
        action="store_true",
        help="actually delete projects (default is a dry run)",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="plan only and write the log without deleting (the default)",
    )

    parser.add_argument(
        "--org",
        action="append",
        dest="orgs",
        metavar="ORG_ID",
        help="restrict the run to this org id (repeatable)",
    )
    parser.add_argument(
        "--delete",
        choices=DELETE_SIDES,
        help="override which side to delete for every org in this run",
    )
    parser.add_argument(
        "--branch-match",
        choices=BRANCH_MATCH_MODES,
        help="override branch matching for every org in this run",
    )
    parser.add_argument(
        "--max-deletes-per-org",
        type=int,
        metavar="N",
        help="skip an org whose plan would delete more than N projects",
    )

    parser.add_argument(
        "--no-exclude-from-future-scans",
        dest="exclude_from_future_scans",
        action="store_false",
        help=(
            "delete SCM projects without excluding them from future scans. "
            "The next SCM sync will recreate them"
        ),
    )

    parser.add_argument(
        "--review",
        action="store_true",
        help="prompt for a decision on each repo before deleting (requires a TTY)",
    )
    parser.add_argument("--log-dir", help="override the log directory from the config")
    parser.add_argument(
        "--log-all-skips",
        action="store_true",
        help=(
            "write a JSONL record for every skipped project and for every eligible "
            "project that found no counterpart, not just triage-worthy ones"
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="log at DEBUG level")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def apply_overrides(config: Config, args: argparse.Namespace) -> tuple[Config, list[str]]:
    """CLI flags win over the config file."""
    notes: list[str] = []

    if args.delete:
        config = replace(config, delete=args.delete)
        notes.append(f"--delete {args.delete} overrides the config file")
    if args.branch_match:
        config = replace(config, branch_match=args.branch_match)
        notes.append(f"--branch-match {args.branch_match} overrides the config file")
    if args.max_deletes_per_org is not None:
        if args.max_deletes_per_org < 1:
            raise ConfigError("--max-deletes-per-org must be a positive integer")
        config = replace(config, max_deletes_per_org=args.max_deletes_per_org)
        notes.append(f"--max-deletes-per-org {args.max_deletes_per_org} applies to every org")
    if args.exclude_from_future_scans is False:
        config = replace(config, exclude_from_future_scans=False)
        notes.append("SCM deletions will NOT be excluded from future scans")
    if args.log_dir:
        config = replace(config, log_dir=args.log_dir)

    return config, notes


def resolve_orgs(client: SnykClient, config: Config, reporter: Reporter) -> list[Org]:
    """Expand the Snyk group (minus exclusions) and merge in explicitly listed orgs."""
    resolved: dict[str, Org] = {}

    if config.group_id:
        reporter.log.info("Listing organizations in group %s", config.group_id)
        for item in client.list_group_orgs(config.group_id):
            attrs = item.get("attributes") or {}
            org = Org(
                id=str(item.get("id") or ""),
                name=attrs.get("name"),
                slug=attrs.get("slug"),
            )
            if not org.id:
                continue
            if config.is_excluded(org.id, org.name, org.slug):
                reporter.log.info("Excluding %s per group.exclude_orgs", org.label)
                reporter.event("org_excluded", org_id=org.id, org_name=org.name, org_slug=org.slug)
                continue
            resolved[org.id.lower()] = org
        reporter.log.info("Group contributed %d organization(s) after exclusions", len(resolved))

    for org_id in config.orgs:
        key = org_id.lower()
        if key in resolved:
            continue
        if config.is_excluded(org_id, None, None):
            reporter.log.warning(
                "Org %s is listed under orgs and also under group.exclude_orgs; "
                "the explicit listing wins",
                org_id,
            )
        try:
            data = client.get_org(org_id)
            attrs = data.get("attributes") or {}
            resolved[key] = Org(id=org_id, name=attrs.get("name"), slug=attrs.get("slug"))
        except SnykApiError as exc:
            reporter.log.warning(
                "Could not read metadata for org %s (%s); continuing with the id only",
                org_id,
                exc,
            )
            resolved[key] = Org(id=org_id)

    return list(resolved.values())


def log_skips(reporter: Reporter, plan: OrgPlan, log_all: bool) -> None:
    for skip in plan.skips:
        if not log_all and skip.reason not in TRIAGE_SKIP_REASONS:
            continue
        reporter.event(
            "skipped",
            org_id=plan.org.id,
            org_name=plan.org.name,
            org_slug=plan.org.slug,
            reason=skip.reason,
            detail=skip.detail,
            project=describe_project(skip.project),
        )


def log_unmatched(reporter: Reporter, plan: OrgPlan) -> None:
    """Record each repo that is monitored from one side only.

    Read these first when a run reports zero duplicates: they show the repo URL
    each side resolved to, which is what had to agree.
    """
    for item in plan.unmatched:
        reporter.event(
            "unmatched",
            org_id=plan.org.id,
            org_name=plan.org.name,
            org_slug=plan.org.slug,
            repo_url=item.repo,
            side=item.side,
            project_count=len(item.projects),
            projects=[describe_project(p, item.repo) for p in item.projects],
        )


def duplicate_event(
    reporter: Reporter,
    plan: OrgPlan,
    duplicate: Duplicate,
    action: str,
) -> None:
    reporter.event(
        "duplicate",
        org_id=plan.org.id,
        org_name=plan.org.name,
        org_slug=plan.org.slug,
        repo_url=duplicate.repo,
        branch_match=plan.config.branch_match,
        delete_side=duplicate.delete_side,
        deleting_count=len(duplicate.to_delete),
        keeping_count=len(duplicate.to_keep),
        coverage_drop=duplicate.coverage_drop,
        action=action,
        exclude_from_future_scans=(
            plan.config.exclude_from_future_scans if duplicate.delete_side == SCM else False
        ),
        deleting=[describe_project(p, duplicate.repo) for p in duplicate.to_delete],
        keeping=[describe_project(p, duplicate.repo) for p in duplicate.to_keep],
    )


def describe_duplicate(duplicate: Duplicate) -> str:
    keep = ", ".join(f"{p.name} [{p.type}]" for p in duplicate.to_keep)
    delete = ", ".join(f"{p.name} [{p.type}]" for p in duplicate.to_delete)
    flag = " COVERAGE DROP" if duplicate.coverage_drop else ""
    return (
        f"{duplicate.repo}{flag}\n"
        f"      keep   -> {len(duplicate.to_keep)} {duplicate.to_keep[0].origin} "
        f"project(s): {keep}\n"
        f"      delete -> {len(duplicate.to_delete)} {duplicate.to_delete[0].origin} "
        f"project(s): {delete}"
    )


def review(plans: Sequence[OrgPlan], reporter: Reporter) -> None:
    """Ask about each repo before deleting. Falls back to the plan when not a TTY."""
    pending = [(plan, duplicate) for plan in plans for duplicate in plan.duplicates]
    if not pending:
        reporter.log.info("--review: nothing to review")
        return
    if not sys.stdin.isatty():
        reporter.log.warning(
            "--review was requested but stdin is not a TTY; "
            "proceeding non-interactively with %d repo(s) as planned",
            len(pending),
        )
        return

    reporter.log.info("Reviewing %d repo(s)", len(pending))
    delete_rest = False
    for index, (plan, duplicate) in enumerate(pending, start=1):
        if delete_rest:
            continue
        print(f"\n[{index}/{len(pending)}] {plan.org.label}")
        print(describe_duplicate(duplicate))
        while True:
            answer = input("  [d]elete as planned / [s]kip / [a]ll / [q]uit review? ").strip().lower()
            if answer in {"d", ""}:
                break
            if answer == "s":
                duplicate.skipped_by_review = True
                reporter.log.info("Skipping %s by review", duplicate.repo)
                break
            if answer == "a":
                delete_rest = True
                reporter.log.info("Accepting all remaining repos as planned")
                break
            if answer == "q":
                for _, remaining in pending[index - 1 :]:
                    remaining.skipped_by_review = True
                reporter.log.info("Review quit; skipping all remaining repos")
                return
            print("  Please answer d, s, a, or q.")


def execute_org(
    client: SnykClient,
    reporter: Reporter,
    plan: OrgPlan,
) -> tuple[int, int]:
    """Delete the planned projects for one org. Returns (deleted, failed)."""
    targets = plan.projects_to_delete()
    if not targets:
        return 0, 0

    by_id = {project.id: (duplicate, project) for duplicate, project in targets}
    ids = [project.id for _, project in targets]
    # Only ever set for SCM deletions: the API applies the exclusion to the
    # target file of an SCM-backed project, which a CLI project does not have.
    exclude = plan.config.exclude_from_future_scans and plan.config.delete == SCM

    deleted_total = 0
    failed_total = 0

    for batch in chunked(ids, MAX_BULK_DELETE):
        reporter.log.info(
            "Deleting %d project(s) in %s (exclude_from_future_scans=%s)",
            len(batch),
            plan.org.label,
            exclude,
        )
        result = client.bulk_delete_projects(plan.org.id, list(batch), exclude)

        reported: set[str] = set()
        for item in result["deleted"]:
            pid = str(item.get("id"))
            reported.add(pid)
            deleted_total += 1
            duplicate, _ = by_id.get(pid, (None, None))
            reporter.event(
                "deletion",
                org_id=plan.org.id,
                org_name=plan.org.name,
                org_slug=plan.org.slug,
                result="deleted",
                exclude_from_future_scans=exclude,
                project_id=pid,
                project_name=item.get("name"),
                repo_url=duplicate.repo if duplicate else None,
                kept=[describe_project(p, duplicate.repo) for p in duplicate.to_keep] if duplicate else [],
            )

        for item in result["failed"]:
            pid = str(item.get("id"))
            reported.add(pid)
            failed_total += 1
            duplicate, _ = by_id.get(pid, (None, None))
            reason = item.get("reason")
            reporter.log.error(
                "Failed to delete %s (%s) in %s: %s",
                item.get("name"),
                pid,
                plan.org.label,
                reason,
            )
            reporter.event(
                "deletion",
                org_id=plan.org.id,
                org_name=plan.org.name,
                org_slug=plan.org.slug,
                result="failed",
                reason=reason,
                exclude_from_future_scans=exclude,
                project_id=pid,
                project_name=item.get("name"),
                repo_url=duplicate.repo if duplicate else None,
                kept=[describe_project(p, duplicate.repo) for p in duplicate.to_keep] if duplicate else [],
            )

        # A project already absent from the org is ignored by the API and
        # appears in neither list.
        for pid in batch:
            if pid in reported:
                continue
            duplicate, project = by_id.get(pid, (None, None))
            reporter.log.warning(
                "Project %s was not reported by the API (already deleted?)", pid
            )
            reporter.event(
                "deletion",
                org_id=plan.org.id,
                org_name=plan.org.name,
                org_slug=plan.org.slug,
                result="not_reported",
                reason="project not present in the org; ignored by the API",
                project_id=pid,
                project_name=project.name if project else None,
                repo_url=duplicate.repo if duplicate else None,
            )

    return deleted_total, failed_total


def plan_org(
    client: SnykClient,
    reporter: Reporter,
    config: Config,
    org: Org,
    log_all_skips: bool = False,
) -> OrgPlan:
    reporter.log.info(
        "Scanning %s (delete=%s, branch_match=%s)",
        org.label,
        config.delete,
        config.branch_match,
    )
    projects = [parse_project(payload) for payload in client.list_projects(org.id)]
    plan = build_plan(org, projects, config)

    skips = plan.skip_counts()
    reporter.log.info(
        "  %d project(s): %d open source, %d duplicate project(s) in %d repo(s)",
        plan.total_projects,
        plan.oss_projects,
        plan.duplicate_project_count,
        len(plan.duplicates),
    )
    if skips:
        reporter.log.info(
            "  skipped: %s",
            ", ".join(f"{reason}={count}" for reason, count in sorted(skips.items())),
        )
    for duplicate in plan.coverage_drops:
        reporter.log.warning(
            "  %s: deleting %d %s project(s) but keeping only %d %s project(s); "
            "the rest of the repo will no longer be monitored",
            duplicate.repo,
            len(duplicate.to_delete),
            duplicate.delete_side,
            len(duplicate.to_keep),
            CLI if duplicate.delete_side == SCM else SCM,
        )
    if plan.unmatched:
        unmatched = plan.unmatched_counts()
        reporter.log.info(
            "  %d repo(s) monitored from one side only (%s)%s",
            len(plan.unmatched),
            ", ".join(f"{side}={count}" for side, count in sorted(unmatched.items())),
            "" if log_all_skips else "; re-run with --log-all-skips to see their repo URLs",
        )
    if plan.type_census:
        reporter.log.debug(
            "  project types seen: %s",
            ", ".join(f"{t}={c}" for t, c in sorted(plan.type_census.items())),
        )
    if plan.capped:
        reporter.log.error(
            "  ABORTING org: plan would delete %d project(s), over max_deletes_per_org=%s",
            plan.delete_count,
            config.max_deletes_per_org,
        )

    reporter.event(
        "org_summary",
        org_id=org.id,
        org_name=org.name,
        org_slug=org.slug,
        delete_side=config.delete,
        branch_match=config.branch_match,
        max_deletes_per_org=config.max_deletes_per_org,
        total_projects=plan.total_projects,
        open_source_projects=plan.oss_projects,
        duplicate_projects=plan.duplicate_project_count,
        duplicate_repos=len(plan.duplicates),
        coverage_drop_repos=len(plan.coverage_drops),
        unmatched_repos=dict(plan.unmatched_counts()),
        projects_to_delete=plan.delete_count,
        capped=plan.capped,
        skips=dict(skips),
        type_census=dict(plan.type_census),
    )
    log_skips(reporter, plan, log_all=log_all_skips)
    if log_all_skips:
        log_unmatched(reporter, plan)
    return plan


def run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    config, notes = apply_overrides(config, args)
    token = read_token()
    dry_run = not args.execute

    with Reporter(config.log_dir, dry_run=dry_run, verbose=args.verbose) as reporter:
        log = reporter.log
        log.info("snyk-hybrid-project-manager %s", __version__)
        log.info("Mode: %s", "DRY RUN (no deletions)" if dry_run else "EXECUTE (deletions enabled)")
        log.info("Log files: %s | %s", reporter.text_path, reporter.jsonl_path)
        for note in notes:
            log.warning("Override: %s", note)

        reporter.event(
            "run_start",
            version=__version__,
            api_url=config.api_url,
            api_version=config.api_version,
            delete=config.delete,
            branch_match=config.branch_match,
            exclude_from_future_scans=config.exclude_from_future_scans,
            max_deletes_per_org=config.max_deletes_per_org,
            group_id=config.group_id,
            overrides=notes,
        )

        client = SnykClient(
            base_url=config.api_url,
            token=token,
            api_version=config.api_version,
            auth_scheme=config.auth_scheme,
            timeout=REQUEST_TIMEOUT,
            max_retries=MAX_RETRIES,
        )

        try:
            orgs = resolve_orgs(client, config, reporter)
        except SnykApiError as exc:
            log.error("Could not resolve organizations: %s", exc)
            reporter.event("run_failed", error=str(exc), status=exc.status)
            return EXIT_FATAL

        if args.orgs:
            wanted = {o.lower() for o in args.orgs}
            missing = wanted - {o.id.lower() for o in orgs}
            for org_id in sorted(missing):
                log.warning("--org %s is not in the resolved org list; ignoring", org_id)
            orgs = [o for o in orgs if o.id.lower() in wanted]

        if not orgs:
            log.error("No organizations to process")
            reporter.event("run_failed", error="no organizations to process")
            return EXIT_CONFIG_ERROR

        log.info("Processing %d organization(s)", len(orgs))

        plans: list[OrgPlan] = []
        failed_orgs = 0
        for org in orgs:
            try:
                plans.append(plan_org(client, reporter, config, org, args.log_all_skips))
            except SnykApiError as exc:
                failed_orgs += 1
                log.error("Skipping %s: %s", org.label, exc)
                reporter.event(
                    "org_failed",
                    org_id=org.id,
                    org_name=org.name,
                    error=str(exc),
                    status=exc.status,
                )

        if args.review:
            review(plans, reporter)

        deleted_total = 0
        failed_total = 0
        planned_total = 0
        blocked_total = 0

        for plan in plans:
            for duplicate in plan.duplicates:
                if plan.capped:
                    action = "blocked_by_max_deletes"
                    blocked_total += len(duplicate.to_delete)
                elif duplicate.skipped_by_review:
                    action = "skipped_by_review"
                    blocked_total += len(duplicate.to_delete)
                elif dry_run:
                    action = "would_delete"
                    planned_total += len(duplicate.to_delete)
                else:
                    action = "delete"
                    planned_total += len(duplicate.to_delete)
                duplicate_event(reporter, plan, duplicate, action)

            if dry_run or plan.capped:
                continue
            try:
                deleted, failed = execute_org(client, reporter, plan)
                deleted_total += deleted
                failed_total += failed
            except SnykApiError as exc:
                failed_orgs += 1
                log.error("Deletion failed for %s: %s", plan.org.label, exc)
                reporter.event(
                    "org_failed",
                    org_id=plan.org.id,
                    org_name=plan.org.name,
                    error=str(exc),
                    status=exc.status,
                )

        capped_orgs = [p.org.id for p in plans if p.capped]
        duplicate_total = sum(p.duplicate_project_count for p in plans)
        repo_total = sum(len(p.duplicates) for p in plans)
        coverage_total = sum(len(p.coverage_drops) for p in plans)

        log.info("-" * 72)
        log.info("Organizations processed        : %d", len(plans))
        log.info(
            "Duplicate projects found      : %d in %d repo(s)",
            duplicate_total,
            repo_total,
        )
        if dry_run:
            log.info("Projects that WOULD be deleted: %d", planned_total)
        else:
            log.info("Projects deleted              : %d", deleted_total)
            log.info("Deletions failed              : %d", failed_total)
        if blocked_total:
            log.info(
                "Projects left untouched       : %d (capped or skipped by review)",
                blocked_total,
            )
        if capped_orgs:
            log.error("Orgs blocked by max_deletes_per_org: %s", ", ".join(capped_orgs))
        if failed_orgs:
            log.error("Organizations with API failures: %d", failed_orgs)
        log.info("Detailed log: %s", reporter.text_path)
        log.info("JSONL log   : %s", reporter.jsonl_path)

        reporter.event(
            "run_summary",
            organizations=len(plans),
            duplicate_projects=duplicate_total,
            duplicate_repos=repo_total,
            coverage_drop_repos=coverage_total,
            projects_planned=planned_total,
            projects_deleted=deleted_total,
            deletions_failed=failed_total,
            projects_blocked=blocked_total,
            orgs_capped=capped_orgs,
            orgs_failed=failed_orgs,
        )

        if failed_orgs or failed_total or capped_orgs:
            return EXIT_PARTIAL_FAILURE
        return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FATAL
