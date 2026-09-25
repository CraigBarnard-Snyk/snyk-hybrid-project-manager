# snyk-hybrid-project-manager

A utility for Snyk estates running a hybrid integration — the Snyk CLI for Open Source and an SCM
integration for Snyk Code. In that setup the SCM integration also imports Open Source projects, so
every repository ends up with two copies of each manifest: one from `snyk monitor`, one from the SCM
sync. This tool finds those duplicates and deletes one side.

Designed to run unattended on a cron. **It is a dry run unless you pass `--execute`.**

## What it does

For each organization in scope:

1. Lists every project via `GET /rest/orgs/{org_id}/projects?expand=target`.
2. Discards anything that isn't an active Open Source project — Snyk Code, Container, and IaC types
   are never touched (see [Which projects are eligible](#which-projects-are-eligible)).
3. Groups what is left by repository, and finds the repos covered by **both** the CLI and an SCM
   integration.
4. Deletes every Open Source project on one side of those repos via
   `POST /rest/orgs/{org_id}/projects/bulk-delete`, with `exclude_from_future_scans` set so the SCM
   sync doesn't recreate what it just deleted.
5. Writes a human-readable log and a JSONL log naming every project deleted, kept, or skipped.

## How duplicates are matched

**Matching is per repository.** If a repo has Open Source projects from the CLI *and* from an SCM
integration, it is being monitored twice, and one side is redundant. Every Open Source project on the
losing side is deleted.

Manifest paths play no part. `package.json` at the root and `frontend/package.json` are not lined up
against each other, and neither is `package.json` against `pom.xml`. The CLI and the SCM integration
disagree about `target_file` constantly — a plain `snyk monitor` reports none at all — so a path-based
rule would be guesswork. The repo is the thing both sides agree on, and one repo URL is the entire
match key: `relationships.target.data.attributes.url`, on both sides.

**Repo URL.** The Snyk CLI picks the repo URL up from `git remote` automatically whenever a `.git`
directory is present in the scanned directory, so `--remote-repo-url` is only needed when it isn't.
That means the CLI side usually carries the SSH form (`git@github.com:acme/api.git`) while the SCM
integration carries the HTTPS form (`https://github.com/acme/api`). Both are canonicalised to
`github.com/acme/api`: scheme, `git@`, credentials, port, `.git`, and trailing slashes are stripped,
the result is lower-cased, and the routing segments Bitbucket Server (`/scm/`) and Azure DevOps
(`/_git/`) insert are dropped.

If CI clones from a mirror whose hostname differs from the one the SCM integration recorded, the two
sides will not match. Those repos show up as `unmatched` with two different `repo_url` values.

**A CLI project with no repo URL is skipped, never guessed at.** It is logged under
`reason: no_repo_url` so you can go fix the pipeline that scanned without a `.git` directory.

**Branch.** The branch is not part of the match either — `snyk monitor` does not record one unless
the run passes `--target-reference`. `branch_match` controls which SCM projects are *eligible*:

- `ignore` (default) — branch plays no part.
- `scm_default` — only count SCM projects on the repo's default branch, and only delete those. The
  REST API does not expose a target's default branch, so this uses a heuristic: the first name in
  `default_branches` (`main`, then `master`) that the repo actually has, otherwise the branch
  carrying the most projects. The chosen branch, and every SCM project skipped for being on another
  branch, are written to the log.

**Coverage drops.** Deleting a side that covers more manifests than the winner leaves part of the
repo unmonitored. If CI runs `snyk monitor` on one manifest while the SCM integration covers ten,
`delete: scm` removes all ten and keeps one. That is what matching per repo means, so the tool does
it — but it warns:

```
WARNING  github.com/acme/api: deleting 10 scm project(s) but keeping only 1 cli project(s);
         the rest of the repo will no longer be monitored
```

and sets `coverage_drop: true` on the log record. **Read these before your first `--execute`.** Run
with `--review` from a terminal to be prompted per repo; on a cron (no TTY) the flag warns and
proceeds as planned.

## Which projects are eligible

Eligibility is an **allowlist**: a project is eligible only if its `type` is a recognised Open Source
package manager — `npm`, `yarn`, `yarn-workspace`, `pnpm`, `maven`, `gradle`, `sbt`, `pip`, `poetry`,
`pipenv`, `nuget`, `paket`, `composer`, `rubygems`, `gomodules`, `golang`, `golangdep`, `govendor`,
`cocoapods`, `swift`, `swiftpm`, `hex`, `cargo`, `cpp`, `conan` (`OSS_TYPES` in
[`config.py`](snyk_hybrid_project_manager/config.py)).

Everything else is skipped: Snyk Code, Container, IaC, **and any project type this tool has not been
told about**. An allowlist fails the safe way — if Snyk ships a new product tomorrow, its projects
are skipped rather than assumed to be Open Source and deleted. The cost is that a newly supported
package manager needs a one-line addition; every run records a census of every type it saw in
`org_summary`, so an unrecognised type shows up in the report rather than silently vanishing.

Also skipped, and logged: inactive projects, and projects whose `origin` is in neither the CLI nor
the SCM list (for example `api`, whose provenance is ambiguous).

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Requires Python 3.10+.

## Authentication

The token is read from the environment only — never from the config file:

```bash
export SNYK_TOKEN=<service account token>
```

The token needs **View Projects** (`org.project.read`) and **Remove Projects**
(`org.project.delete`) in every org in scope. `SNYK_API` is not read; set the regional tenant with
`api_url` in the config (`https://api.eu.snyk.io`, `https://api.au.snyk.io`).

## Usage

```bash
# Dry run: plan and log, delete nothing. This is the default.
.venv/bin/python -m snyk_hybrid_project_manager --config config.yaml

# Review the plan, then run it for real.
.venv/bin/python -m snyk_hybrid_project_manager --config config.yaml --execute

# Try a single org first.
.venv/bin/python -m snyk_hybrid_project_manager --config config.yaml --org <org-uuid>
```

### Flags

| Flag | Effect |
|---|---|
| `--config PATH` | Required. Path to the YAML config. |
| `--execute` | Actually delete. Without it the run is a dry run. |
| `--dry-run` | Explicitly request the default behaviour. |
| `--org ORG_ID` | Restrict the run to this org id. Repeatable. |
| `--delete {scm,cli}` | Override which side to delete, for every org. |
| `--branch-match {ignore,scm_default}` | Override branch handling, for every org. |
| `--max-deletes-per-org N` | Skip any org whose plan exceeds N deletions. |
| `--no-exclude-from-future-scans` | Delete SCM projects without excluding them from future scans. |
| `--review` | Prompt per repo before deleting (requires a TTY). |
| `--log-dir PATH` | Override the log directory. |
| `--log-all-skips` | Write a JSONL record for every skipped project and every unmatched one. |
| `--verbose` | DEBUG-level logging. |

Command-line flags override the config file, and each override is logged as a warning at the top of
the run.

### Cron

```cron
30 2 * * * cd /opt/snyk-hybrid-project-manager && SNYK_TOKEN=$(cat /etc/snyk/token) \
  .venv/bin/python -m snyk_hybrid_project_manager --config config.yaml --execute >> /var/log/snyk-hybrid.log 2>&1
```

Note the explicit `--execute`: a bare invocation, or a misconfigured cron entry, can only ever
produce a dry run.

## Configuration

There is one decision — which side to delete — and one list of orgs to apply it to:

```yaml
delete: scm              # or: cli
orgs:
  - aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

Or by Snyk group, which processes every org in it:

```yaml
delete: scm
group:
  id: 11111111-2222-3333-4444-555555555555
  exclude_orgs:
    - sandbox-org
```

`group` and `orgs` can both be given; the union is processed. An org listed explicitly under `orgs`
is always processed, even if it also appears in `group.exclude_orgs` — the explicit listing is more
specific, and the conflict is logged.

One set of settings applies to every org in a run. If two orgs need different settings, run the tool
twice with two config files.

Everything else is optional and rarely touched: `api_url` (regional tenant), `branch_match`,
`default_branches`, `max_deletes_per_org`, `log_dir`, `auth_scheme`, and `api_version` (which must be
`2024-10-15` or later — the first Snyk REST version exposing `bulk-delete`; default `2026-03-25`).
See [`config.example.yaml`](config.example.yaml) for the commented reference.

## Deletion semantics

Excluding a deleted project from future scans is **always on**: a deleted SCM project that isn't
excluded is recreated by the next sync, which would make the whole run pointless. It adds the deleted
project's target file to the repository's test exclusions for that branch.

Two things worth knowing:

- **It only ever applies to SCM deletions.** The API applies the exclusion to the target file of an
  SCM-backed project; a CLI project has no repo path to exclude. When the config deletes the CLI
  side, the flag is always sent as `false`.
- **A repository supports at most 100 test exclusions.** Past that the API returns the project in
  `meta.failed` with `exclusion_limit_reached` and **does not delete it**. The tool logs the failure
  with the project id and reason, and exits non-zero; it does not silently retry without the
  exclusion, because that would delete a project the SCM sync would immediately recreate.

To reverse an exclusion, re-import the repository from the Organization or Group level. Re-imported
projects are new projects and do not carry over issue history.

## Logs

Each run writes two files to `log_dir` (default `./logs`), named `run-<UTC timestamp>`:

- `run-….log` — human-readable, also mirrored to stdout for cron mail.
- `run-….jsonl` — one JSON object per decision.

Dry runs write exactly the same artifacts, so a dry run can be reviewed, diffed, or fed to another
tool before anything is deleted.

A *duplicate* is a repo covered by both the CLI and an SCM integration. Project counts reported about
them count projects, so `4 duplicate project(s) in 2 repo(s)` means four projects are the redundant
copy, spread across two repos.

JSONL event types:

| `event` | Meaning |
|---|---|
| `run_start` | Effective settings for the run, including any CLI overrides. |
| `org_excluded` | An org in the Snyk group was skipped per `exclude_orgs`. |
| `org_summary` | Per-org counts, skip reasons, and the project-type census. `duplicate_projects` is the number of projects on the losing side; `duplicate_repos` is how many repos they came from; `coverage_drop_repos` is how many of those repos lose monitoring coverage; `projects_to_delete` is what this run would actually remove (lower when a repo was capped or skipped by review); `unmatched_repos` counts one-sided repos per side. |
| `skipped` | A project excluded from matching. Reasons `no_repo_url`, `origin_not_classified`, and `non_default_branch` get a record each; `non_oss_type` and `inactive` are counted in `org_summary` unless `--log-all-skips`. |
| `unmatched` | A repo monitored from one side only. Carries `repo_url`, `side`, `project_count`, and `projects[]`. One record per repo, written with `--log-all-skips`. Read these first when a run reports zero duplicates — the `repo_url` each side resolved to is what had to agree. |
| `duplicate` | A repo covered by both sides. Carries `repo_url`, `deleting[]`, `keeping[]`, `deleting_count`, `keeping_count`, `coverage_drop`, and `action` (`would_delete`, `delete`, `blocked_by_max_deletes`, `skipped_by_review`). |
| `deletion` | The API result per project: `deleted`, `failed` (with `reason`), or `not_reported`. Each record repeats the kept project so the line stands alone. |
| `org_failed` / `run_failed` | An API failure that stopped an org or the run. |
| `run_summary` | Totals. |

Find everything a dry run would delete, and what it would keep in its place:

```bash
jq -r 'select(.event=="duplicate") | "\(.repo_url)  DELETE \(.deleting[].name)  KEEP \(.keeping[].name)"' logs/run-*.jsonl
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Partial failure: a deletion failed, an org hit its cap, or an org errored. |
| 2 | Configuration, authentication, or usage error; nothing ran. |
| 3 | Fatal error resolving organizations, or interrupted. |

## Reliability

- 429 responses honour `Retry-After`; 429/5xx and transport errors retry with exponential backoff
  and jitter, up to 5 attempts. Other 4xx responses fail immediately.
- Retrying a `bulk-delete` is safe: the endpoint ignores project ids that no longer exist in the org.
- Bulk deletes are batched at the API maximum of 100 projects. A partially successful batch still
  returns 200, so both `meta.deleted` and `meta.failed` are read and logged.
- Orgs are processed sequentially, and an org that fails does not stop the run.

## Known limitations

- `branch_match: scm_default` infers the default branch heuristically; the REST API does not expose
  it. The inferred branch is logged.
- Canonical repo URLs are lower-cased, so two repos on the same host differing only in case would
  collide.
- Matching per repo means a partial scan on the winning side deletes full coverage on the losing
  side. See **Coverage drops** above; these are warned about, not blocked.
- A repo whose SCM integration monitors several branches has SCM projects on each. With
  `branch_match: ignore` all of them are deleted. Use `branch_match: scm_default` to delete only the
  default branch's projects and leave the others monitored.
- A newly supported package manager is skipped until its type is added to `OSS_TYPES`. It appears in
  the `org_summary` type census.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

The matching and planning logic is pure and covered offline — no API access needed.

## License

MIT. See [LICENSE](LICENSE).
