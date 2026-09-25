import unittest

from snyk_hybrid_project_manager.config import Config
from snyk_hybrid_project_manager.matching import CLI, SCM, Project
from snyk_hybrid_project_manager.planner import (
    SKIP_INACTIVE,
    SKIP_NON_DEFAULT_BRANCH,
    SKIP_NON_OSS_TYPE,
    SKIP_NO_REPO_URL,
    SKIP_UNCLASSIFIED_ORIGIN,
    Org,
    build_plan,
)

ORG = Org(id="org-1", name="Acme", slug="acme")


def project(
    pid,
    origin,
    *,
    name=None,
    ptype="npm",
    target_file="package.json",
    ref="main",
    status="active",
    url="https://github.com/acme/api",
    created="2024-01-01T00:00:00Z",
    display_name="acme/api",
):
    return Project(
        id=pid,
        name=name or f"{origin}-{pid}",
        origin=origin,
        type=ptype,
        target_file=target_file,
        target_reference=ref,
        status=status,
        created=created,
        target_id=f"target-{pid}",
        target_url=url,
        target_display_name=display_name,
    )


def config(**overrides):
    base = dict(orgs=(ORG.id,))
    base.update(overrides)
    return Config(**base)


class RepoMatchingTests(unittest.TestCase):
    """Matching is per repo. The manifest path plays no part."""

    def test_a_repo_covered_by_both_sides_deletes_the_scm_side_by_default(self):
        plan = build_plan(ORG, [project("a", "cli"), project("b", "github")], config())
        self.assertEqual(len(plan.duplicates), 1)
        duplicate = plan.duplicates[0]
        self.assertEqual(duplicate.repo, "github.com/acme/api")
        self.assertEqual([p.id for p in duplicate.to_delete], ["b"])
        self.assertEqual([p.id for p in duplicate.to_keep], ["a"])
        self.assertEqual(plan.delete_count, 1)

    def test_configuring_the_cli_side_deletes_the_cli_project(self):
        plan = build_plan(
            ORG, [project("a", "cli"), project("b", "github")], config(delete="cli")
        )
        duplicate = plan.duplicates[0]
        self.assertEqual([p.id for p in duplicate.to_delete], ["a"])
        self.assertEqual([p.id for p in duplicate.to_keep], ["b"])

    def test_ssh_cli_url_matches_https_scm_url(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", url="git@github.com:acme/api.git"),
                project("b", "github", url="https://github.com/acme/api"),
            ],
            config(),
        )
        self.assertEqual(len(plan.duplicates), 1)

    def test_different_manifest_paths_in_one_repo_still_match(self):
        # The whole point of matching per repo: root/package.json and
        # root/frontend/package.json are not lined up against each other.
        plan = build_plan(
            ORG,
            [
                project("a", "cli", target_file=""),
                project("b", "github", target_file="frontend/package.json"),
            ],
            config(),
        )
        self.assertEqual(len(plan.duplicates), 1)
        self.assertEqual([p.id for p in plan.duplicates[0].to_delete], ["b"])

    def test_different_package_managers_in_one_repo_still_match(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", ptype="npm", target_file="package.json"),
                project("b", "github", ptype="maven", target_file="pom.xml"),
            ],
            config(),
        )
        self.assertEqual(len(plan.duplicates), 1)
        self.assertEqual([p.id for p in plan.duplicates[0].to_delete], ["b"])

    def test_every_open_source_project_on_the_losing_side_is_deleted(self):
        projects = [project("cli-1", "cli", target_file="")]
        projects += [
            project("scm-1", "github", target_file="package.json"),
            project("scm-2", "github", target_file="services/api/package.json"),
            project("scm-3", "github", ptype="maven", target_file="services/db/pom.xml"),
        ]
        plan = build_plan(ORG, projects, config())
        self.assertEqual(len(plan.duplicates), 1)
        self.assertEqual(
            [p.id for p in plan.duplicates[0].to_delete], ["scm-1", "scm-2", "scm-3"]
        )
        self.assertEqual(plan.delete_count, 3)

    def test_non_open_source_projects_are_never_part_of_a_repo_match(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli"),
                project("b", "github"),
                project("c", "github", ptype="sast", target_file=""),
                project("d", "github", ptype="dockerfile", target_file="Dockerfile"),
            ],
            config(),
        )
        self.assertEqual([p.id for p in plan.duplicates[0].to_delete], ["b"])

    def test_different_repos_do_not_match(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", url="https://github.com/acme/api"),
                project("b", "github", url="https://github.com/acme/web"),
            ],
            config(),
        )
        self.assertEqual(plan.duplicates, [])

    def test_a_repo_with_one_side_only_is_left_alone(self):
        plan = build_plan(
            ORG,
            [project("a", "cli"), project("b", "cli", target_file="frontend/package.json")],
            config(),
        )
        self.assertEqual(plan.duplicates, [])
        self.assertEqual(plan.delete_count, 0)


class CoverageDropTests(unittest.TestCase):
    """Deleting a side that covers more manifests than the winner loses coverage."""

    def test_flagged_when_the_losing_side_is_larger(self):
        plan = build_plan(
            ORG,
            [
                project("cli-1", "cli", target_file=""),
                project("scm-1", "github", target_file="package.json"),
                project("scm-2", "github", target_file="frontend/package.json"),
            ],
            config(),
        )
        duplicate = plan.duplicates[0]
        self.assertTrue(duplicate.coverage_drop)
        self.assertEqual(plan.coverage_drops, [duplicate])

    def test_not_flagged_when_the_sides_are_even(self):
        plan = build_plan(ORG, [project("a", "cli"), project("b", "github")], config())
        self.assertFalse(plan.duplicates[0].coverage_drop)
        self.assertEqual(plan.coverage_drops, [])

    def test_not_flagged_when_the_winning_side_covers_more(self):
        plan = build_plan(
            ORG,
            [
                project("cli-1", "cli", target_file="package.json"),
                project("cli-2", "cli", target_file="frontend/package.json"),
                project("scm-1", "github", target_file="package.json"),
            ],
            config(),
        )
        self.assertFalse(plan.duplicates[0].coverage_drop)

    def test_the_flag_follows_the_delete_side(self):
        projects = [
            project("cli-1", "cli", target_file=""),
            project("scm-1", "github", target_file="package.json"),
            project("scm-2", "github", target_file="frontend/package.json"),
        ]
        self.assertTrue(build_plan(ORG, projects, config()).duplicates[0].coverage_drop)
        self.assertFalse(
            build_plan(ORG, projects, config(delete="cli")).duplicates[0].coverage_drop
        )


class SkipTests(unittest.TestCase):
    def test_non_oss_types_are_never_touched(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", ptype="sast"),
                project("b", "github", ptype="sast"),
                project("c", "cli", ptype="dockerfile"),
                project("d", "github", ptype="terraformconfig"),
            ],
            config(),
        )
        self.assertEqual(plan.duplicates, [])
        self.assertEqual(plan.skip_counts()[SKIP_NON_OSS_TYPE], 4)
        self.assertEqual(plan.oss_projects, 0)

    def test_unknown_type_is_recorded_in_the_census_even_though_it_is_skipped(self):
        """A new package manager shows up in the report before it can be deleted."""
        plan = build_plan(
            ORG,
            [
                project("a", "cli", ptype="brand-new-pm"),
                project("b", "github", ptype="brand-new-pm"),
            ],
            config(),
        )
        self.assertEqual(plan.duplicates, [])
        self.assertEqual(plan.type_census["brand-new-pm"], 2)
        self.assertEqual(plan.skip_counts()[SKIP_NON_OSS_TYPE], 2)

    def test_inactive_projects_are_skipped(self):
        plan = build_plan(
            ORG,
            [project("a", "cli"), project("b", "github", status="inactive")],
            config(),
        )
        self.assertEqual(plan.duplicates, [])
        self.assertEqual(plan.skip_counts()[SKIP_INACTIVE], 1)

    def test_unclassified_origin_is_skipped(self):
        plan = build_plan(
            ORG, [project("a", "cli"), project("b", "api")], config()
        )
        self.assertEqual(plan.duplicates, [])
        self.assertEqual(plan.skip_counts()[SKIP_UNCLASSIFIED_ORIGIN], 1)

    def test_missing_repo_url_is_skipped_not_guessed(self):
        plan = build_plan(
            ORG,
            [project("a", "cli", url=None), project("b", "github")],
            config(),
        )
        self.assertEqual(plan.duplicates, [])
        skip = next(s for s in plan.skips if s.reason == SKIP_NO_REPO_URL)
        self.assertEqual(skip.detail, "acme/api")


class ReviewTests(unittest.TestCase):
    def test_review_skip_removes_the_repo_from_the_plan(self):
        plan = build_plan(ORG, [project("a", "cli"), project("b", "github")], config())
        plan.duplicates[0].skipped_by_review = True
        self.assertEqual(plan.active_duplicates, [])
        self.assertEqual(plan.delete_count, 0)
        # Still counted as found, so the report shows what was passed over.
        self.assertEqual(plan.duplicate_project_count, 1)


class BranchMatchTests(unittest.TestCase):
    def test_branches_never_have_to_agree(self):
        # `snyk monitor` records no branch, so a CLI project with none still
        # matches a repo the SCM integration monitors on its default branch.
        plan = build_plan(
            ORG,
            [project("a", "cli", ref=""), project("b", "github", ref="main")],
            config(),
        )
        self.assertEqual(len(plan.duplicates), 1)

    def test_ignore_matches_across_branches(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", ref="feature/x"),
                project("b", "github", ref="main"),
            ],
            config(),
        )
        self.assertEqual(len(plan.duplicates), 1)

    def test_scm_default_ignores_scm_projects_on_other_branches(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", ref="feature/x"),
                project("b", "github", ref="main"),
                project("c", "github", ref="release"),
            ],
            config(branch_match="scm_default"),
        )
        self.assertEqual(len(plan.duplicates), 1)
        self.assertEqual([p.id for p in plan.duplicates[0].to_delete], ["b"])
        skip = next(s for s in plan.skips if s.reason == SKIP_NON_DEFAULT_BRANCH)
        self.assertEqual(skip.project.id, "c")
        self.assertEqual(skip.detail, "release != main")

    def test_scm_default_falls_back_to_the_busiest_branch(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli"),
                project("b", "github", ref="develop", target_file="one.json"),
                project("c", "github", ref="develop", target_file="two.json"),
                project("d", "github", ref="release"),
            ],
            config(branch_match="scm_default"),
        )
        self.assertEqual({p.id for p in plan.duplicates[0].to_delete}, {"b", "c"})


class SafetyCapTests(unittest.TestCase):
    def _plan_with_cap(self, cap):
        projects = [project("cli-1", "cli")]
        for index in range(3):
            projects.append(
                project(f"scm-{index}", "github", target_file=f"pkg{index}/package.json")
            )
        return build_plan(ORG, projects, config(max_deletes_per_org=cap))

    def test_plan_over_the_cap_is_flagged(self):
        plan = self._plan_with_cap(2)
        self.assertTrue(plan.capped)
        self.assertEqual(plan.delete_count, 3)

    def test_plan_within_the_cap_is_not_flagged(self):
        self.assertFalse(self._plan_with_cap(3).capped)

    def test_no_cap_by_default(self):
        self.assertFalse(build_plan(ORG, [], config()).capped)


class UnmatchedTests(unittest.TestCase):
    def test_a_one_sided_repo_is_recorded_once_with_all_its_projects(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", target_file="package.json"),
                project("b", "cli", target_file="frontend/package.json"),
            ],
            config(),
        )
        self.assertEqual(len(plan.unmatched), 1)
        item = plan.unmatched[0]
        self.assertEqual(item.side, CLI)
        self.assertEqual(item.repo, "github.com/acme/api")
        self.assertEqual([p.id for p in item.projects], ["a", "b"])

    def test_skipped_projects_are_not_also_reported_as_unmatched(self):
        plan = build_plan(ORG, [project("a", "cli", ptype="sast")], config())
        self.assertEqual(plan.unmatched, [])

    def test_counts_are_repos_broken_down_by_side(self):
        plan = build_plan(
            ORG,
            [
                project("a", "cli", url="https://github.com/acme/one"),
                project("b", "github", url="https://github.com/acme/two"),
                project("c", "github", url="https://github.com/acme/three"),
            ],
            config(),
        )
        self.assertEqual(dict(plan.unmatched_counts()), {CLI: 1, SCM: 2})


if __name__ == "__main__":
    unittest.main()
