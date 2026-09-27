# snyk-hybrid-project-manager

If you use the Snyk CLI for Open Source and an SCM integration for Snyk Code, you end up with
duplicate projects: the SCM integration imports Open Source projects too, so each manifest is
monitored twice, once by `snyk monitor` and once by the SCM sync.

This tool finds those duplicates and deletes one side. It runs fine on a cron.

**Nothing is deleted unless you pass `--execute`.**

> **Use at your own risk.** This is a community project, not an official Snyk product, and it is not
> supported by Snyk. It is provided as is, with no warranty and no guarantee of correctness. It
> deletes projects, and deletion cannot be undone: re-imported projects are new projects and lose
> their issue history. Run it as a dry run, read the plan, and test against an org you don't care
> about before pointing it at one you do.

## What it does

For each organization in scope:

1. Lists every project (`GET /rest/orgs/{org_id}/projects?expand=target`).
2. Drops anything that isn't an active Open Source project. Snyk Code, Container, and IaC are never
   touched — see [Which projects are eligible](#which-projects-are-eligible).
3. Groups the rest by repository and finds the repos covered by **both** the CLI and an SCM
   integration.
4. Deletes every Open Source project on one side of those repos
   (`POST /rest/orgs/{org_id}/projects/bulk-delete`), setting `exclude_from_future_scans` so the SCM
   sync doesn't recreate them.
5. Logs every project deleted, kept, or skipped, as text and as JSONL.

## How duplicates are matched

**Matching is per repository.** If a repo has Open Source projects from both sides, it is monitored
twice and one side is redundant. Every Open Source project on the losing side is deleted.

Manifest paths are not compared — the two sides disagree about `target_file` too often, and a plain
`snyk monitor` reports no path at all. The repo URL is the one thing both sides agree on, so it is
the whole match key.

**Repo URL.** The CLI reads it from `git remote` when a `.git` directory is present, so it usually
reports the SSH form (`git@github.com:acme/api.git`) while the SCM side reports HTTPS
(`https://github.com/acme/api`). Both reduce to `github.com/acme/api`: scheme, `git@`, credentials,
port, `.git` and trailing slashes are stripped, the result is lower-cased, and the extra segments
Bitbucket Server (`/scm/`) and Azure DevOps (`/_git/`) add are removed.

If CI clones from a mirror with a different hostname, the sides won't match. Those repos appear as
`unmatched` with two different `repo_url` values. A CLI project with no repo URL is skipped, not
guessed at, and logged under `reason: no_repo_url`.

**Branches** are not compared either, since `snyk monitor` records one only with
`--target-reference`. `branch_match` controls which SCM projects are *eligible*:

- `ignore` (default) — branches aren't considered.
- `scm_default` — only count and delete SCM projects on the repo's default branch. The API doesn't
  expose that, so the tool guesses: the first of `default_branches` (`main`, then `master`) the repo
  has, else the branch with the most projects. Its choice is logged.

**Coverage drops.** If CI scans one manifest while the SCM integration covers ten, `delete: scm`
removes all ten and keeps one, leaving the rest of the repo unmonitored. That follows from matching
per repo, so the tool goes ahead, but warns and sets `coverage_drop: true` on the record:

```
WARNING  github.com/acme/api: deleting 10 scm project(s) but keeping only 1 cli project(s);
         the rest of the repo will no longer be monitored
```

**Read these before your first `--execute`.** `--review` asks about each repo from a terminal; on a
cron there's no TTY, so it warns and carries on as planned.

### Looser matching: `match_level: org`

`match_level: org` (or `--match-level org`) stops comparing repo URLs altogether. If an org holds
even one Open Source project on the side you're keeping, **every** Open Source project on the side
you're deleting goes, whatever repo it belongs to. An org with nothing on the keeping side loses
nothing.

With `delete: scm`, one CLI project anywhere in the org condemns every SCM-imported Open Source
project in it. With `delete: cli` it works the other way round.

Use it when you know an org has moved to CLI scanning wholesale and you want the SCM-imported Open
Source projects gone, including in repos the CLI hasn't reached yet. The trade-off is blunt: repos
covered only by the SCM integration lose Open Source monitoring entirely, and repo-by-repo
`coverage_drop` warnings no longer tell you which, because there is no per-repo comparison left to
make. Every affected project is still named in the log with its own repo URL.

Everything else is unchanged. Snyk Code, Container and IaC are never touched, inactive and
unclassified projects are still skipped, and `max_deletes_per_org` still caps the damage. The one
other difference is that a project with no repo URL is no longer skipped: nothing is being matched on
a URL, so a CLI project scanned without a `.git` directory still counts as evidence.

The run log says so at the top, and the plan is recorded under `repo_url: <entire org>`:

```
WARNING  Match level: ORG. Repo URLs are not compared. In any org holding at least one open
         source cli project, EVERY open source scm project is deleted, whatever repo it
         belongs to. Read the dry run before using --execute.
```

## Which projects are eligible

Only these types: `npm`, `yarn`, `yarn-workspace`, `pnpm`, `maven`, `gradle`, `sbt`, `pip`, `poetry`,
`pipenv`, `nuget`, `paket`, `composer`, `rubygems`, `gomodules`, `golang`, `golangdep`, `govendor`,
`cocoapods`, `swift`, `swiftpm`, `hex`, `cargo`, `cpp`, `conan` (`OSS_TYPES` in
[`config.py`](snyk_hybrid_project_manager/config.py)).

It's an allowlist on purpose: a type the tool doesn't recognise gets skipped rather than mistaken for
Open Source and deleted, so a new Snyk product is safe by default. The trade-off is that a new
package manager needs adding before the tool will touch it. Every run logs the types it saw in
`org_summary`, so unrecognised ones show up in the report.

Origins on neither list are skipped as well (`api`, for example, where there's no way to tell which
side created it).

### Inactive projects

Inactive projects are skipped by default. A project goes inactive for two reasons the API can't tell
apart: Snyk deactivates one automatically when its manifest is deleted or renamed, but a person can
also deactivate one deliberately, and Snyk won't reactivate those during a sync. Deleting the second
kind throws away a decision someone made, along with the project's history and ignores.

`delete_inactive: true` (or `--delete-inactive`) includes them. Two things stay true when it's on:

- **An inactive project is only ever deleted, never kept.** A repo whose CLI project is inactive
  doesn't lose its live SCM projects, and an org whose only CLI projects are inactive deletes
  nothing. Keeping a dead project in place of a live one would leave the repo unmonitored.
- **Only an explicitly inactive status counts.** A project with a missing or unrecognised status is
  still skipped rather than assumed dead.

Each run reports how many of the projects it would delete are already inactive, so you can see how
much of a plan is tidying and how much is live monitoring.

Note that deleting is not deactivating. If a project was deactivated by hand but its manifest is
still in the repo, deleting it lets the next sync create a **new active** project in its place.
`exclude_from_future_scans` is what stops that, at the cost of one of the repo's 100 exclusion
slots.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Python 3.10+.

## Usage

The token is read from the environment, never the config file. It needs **View Projects**
(`org.project.read`) and **Remove Projects** (`org.project.delete`) in every org you point it at.

```bash
export SNYK_TOKEN=<service account token>

# Dry run: plan and log, delete nothing. The default.
.venv/bin/python -m snyk_hybrid_project_manager --config config.yaml

# Once you've read the plan, run it for real.
.venv/bin/python -m snyk_hybrid_project_manager --config config.yaml --execute

# Try a single org first.
.venv/bin/python -m snyk_hybrid_project_manager --config config.yaml --org <org-uuid>
```

`SNYK_API` is ignored; set your regional tenant with `api_url` in the config.

### Flags

Flags override the config file, and each override is logged as a warning at the top of the run.

| Flag | Effect |
|---|---|
| `--config PATH` | Required. Path to the YAML config. |
| `--execute` | Actually delete. Without it the run is a dry run. |
| `--dry-run` | Ask for the default behaviour explicitly. |
| `--org ORG_ID` | Only process this org id. Repeatable. |
| `--delete {scm,cli}` | Override which side to delete. |
| `--match-level {repo,org}` | Override match strictness. `org` is much looser — see above. |
| `--delete-inactive` | Also delete inactive projects on the side being deleted. |
| `--branch-match {ignore,scm_default}` | Override branch handling. |
| `--max-deletes-per-org N` | Skip any org whose plan exceeds N deletions. |
| `--no-exclude-from-future-scans` | Delete SCM projects without excluding them from future scans. |
| `--review` | Ask about each repo before deleting. Needs a TTY. |
| `--log-dir PATH` | Override the log directory. |
| `--log-all-skips` | Write a record for every skipped and unmatched project. |
| `--verbose` | Log at DEBUG level. |

### Cron

```cron
30 2 * * * cd /opt/snyk-hybrid-project-manager && SNYK_TOKEN=$(cat /etc/snyk/token) \
  .venv/bin/python -m snyk_hybrid_project_manager --config config.yaml --execute >> /var/log/snyk-hybrid.log 2>&1
```

Note the explicit `--execute`. A bare invocation, or a cron entry you got wrong, can only ever
produce a dry run.

## Configuration

One decision — which side to delete — and a list of orgs to apply it to:

```yaml
delete: scm              # or: cli
orgs:
  - aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

Or a Snyk group, which processes every org in it:

```yaml
delete: scm
group:
  id: 11111111-2222-3333-4444-555555555555
  exclude_orgs:
    - sandbox-org
```

Set both and both are processed. An org named under `orgs` is always processed even if it also
appears in `group.exclude_orgs`, since naming it directly is the more specific instruction; the
conflict is logged.

One set of settings applies to every org. If two orgs need different settings, run the tool twice
with two configs.

The rest is optional: `api_url`, `match_level`, `delete_inactive`, `branch_match`,
`default_branches`,
`max_deletes_per_org`,
`log_dir`, `auth_scheme`, and `api_version` (`2024-10-15` or later, the first version with
`bulk-delete`; default `2026-03-25`). [`config.example.yaml`](config.example.yaml) documents them.

## What deletion actually does

Excluding deleted projects from future scans is **always on** — without it the next sync just
recreates them. The exclusion adds the project's target file to the repo's test exclusions for that
branch. Two caveats:

- **SCM deletions only.** The exclusion attaches to an SCM-backed project's target file; a CLI
  project has no repo path to exclude, so the flag is sent as `false` when deleting the CLI side.
- **A repo supports at most 100 test exclusions.** Past that the API returns the project in
  `meta.failed` with `exclusion_limit_reached` and **does not delete it**. The tool logs it and exits
  non-zero rather than retrying without the exclusion, which would delete a project the next sync
  would recreate.

To undo an exclusion, re-import the repository from the Organization or Group level. Re-imported
projects are new projects and don't keep their issue history.

## Logs

Two files per run in `log_dir` (default `./logs`), named `run-<UTC timestamp>`: a `.log` for reading
(also printed to stdout so cron can mail it) and a `.jsonl` with one object per decision. Dry runs
write the same files, so you can read, diff, or script against a plan before anything is deleted.

A *duplicate* is a repo covered by both sides. Counts are of projects, so `4 duplicate project(s) in
2 repo(s)` means four redundant projects across two repos.

| `event` | Meaning |
|---|---|
| `run_start` | Settings in use, including `match_level` and flag overrides. |
| `org_excluded` | Org skipped per `exclude_orgs`. |
| `org_summary` | Per-org counts, skip reasons, and types seen. `projects_to_delete` is what would actually go, which is lower than `duplicate_projects` if a repo was capped or skipped in review; `inactive_projects_to_delete` is how many of those are already inactive. |
| `skipped` | A project left out of matching, with the reason. `non_oss_type` and `inactive` are only counted here unless `--log-all-skips`. |
| `unmatched` | A repo monitored from one side only (`--log-all-skips`). Read these first if a run finds no duplicates: the `repo_url` each side resolved to is what needed to match. |
| `duplicate` | A repo covered by both sides, with `deleting[]`, `keeping[]`, `coverage_drop`, and `action`. Under `match_level: org` there is one record per org instead, with `repo_url: <entire org>`; each project in `deleting[]` still carries its own `canonical_repo_url`. |
| `deletion` | What the API did per project: `deleted`, `failed` with a reason, or `not_reported`. |
| `org_failed` / `run_failed` | An API failure that stopped an org, or the run. |
| `run_summary` | Totals. |

What a dry run would delete, and keep instead:

```bash
jq -r 'select(.event=="duplicate") | "\(.repo_url)  DELETE \(.deleting[].name)  KEEP \(.keeping[].name)"' logs/run-*.jsonl
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Partial failure: a deletion failed, an org hit its cap, or an org errored. |
| 2 | Configuration, authentication, or usage error. Nothing ran. |
| 3 | Couldn't resolve organizations, or interrupted. |

## Reliability

429s honour `Retry-After`; 429s, 5xxs and transport errors retry with exponential backoff and jitter
up to 5 attempts, while other 4xx responses fail straight away. Retrying a `bulk-delete` is safe —
the endpoint ignores ids that are no longer in the org. Deletes are batched at the API maximum of
100; a partly successful batch still returns 200, so both `meta.deleted` and `meta.failed` are read.
Orgs are processed one at a time, and one failing doesn't stop the run.

## Known limitations

- `branch_match: scm_default` guesses the default branch, because the API doesn't expose it.
- Repo URLs are lower-cased, so two repos differing only in case would collide.
- A partial scan on the winning side can delete full coverage on the losing side. You get a warning,
  not a block — see [Coverage drops](#how-duplicates-are-matched).
- If an SCM integration monitors several branches, `branch_match: ignore` deletes the projects on all
  of them. Use `scm_default` to keep the others.
- A new package manager is skipped until its type is added to `OSS_TYPES`.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

The matching and planning logic does no I/O, so the tests run offline with no API access.

## License

MIT. See [LICENSE](LICENSE) for the full text, including the warranty disclaimer: the software is
provided "as is", and the authors are not liable for any claim or damages arising from its use.
