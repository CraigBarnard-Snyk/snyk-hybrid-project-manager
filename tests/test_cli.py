import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from snyk_hybrid_project_manager.cli import (
    EXIT_OK,
    EXIT_PARTIAL_FAILURE,
    EXIT_CONFIG_ERROR,
    main,
)

ORG_ID = "11111111-1111-1111-1111-111111111111"
GROUP_ID = "99999999-9999-9999-9999-999999999999"


def project_payload(pid, origin, target_file="package.json", ptype="npm", ref="main",
                    status="active", url="https://github.com/acme/api", name=None):
    return {
        "id": pid,
        "type": "project",
        "attributes": {
            "name": name or f"acme/api:{target_file}",
            "origin": origin,
            "type": ptype,
            "target_file": target_file,
            "target_reference": ref,
            "status": status,
            "created": "2024-01-01T00:00:00Z",
        },
        "relationships": {
            "target": {
                "data": {
                    "id": f"target-{pid}",
                    "type": "target",
                    "attributes": {"url": url, "display_name": "acme/api"},
                }
            }
        },
    }


class FakeClient:
    def __init__(self, projects, delete_result=None, **kwargs):
        self.projects = projects
        self.delete_calls = []
        self.delete_result = delete_result

    def list_group_orgs(self, group_id):
        return [
            {"id": ORG_ID, "attributes": {"name": "Acme", "slug": "acme"}},
        ]

    def get_org(self, org_id):
        return {"id": org_id, "attributes": {"name": "Acme", "slug": "acme"}}

    def list_projects(self, org_id):
        return iter(self.projects)

    def bulk_delete_projects(self, org_id, project_ids, exclude_from_future_scans):
        self.delete_calls.append(
            {"org": org_id, "ids": list(project_ids), "exclude": exclude_from_future_scans}
        )
        if self.delete_result is not None:
            return self.delete_result
        return {
            "deleted": [{"id": pid, "name": f"project-{pid}"} for pid in project_ids],
            "failed": [],
        }


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log_dir = Path(self.tmp.name) / "logs"
        env = mock.patch.dict(os.environ, {"SNYK_TOKEN": "fake-token"})
        env.start()
        self.addCleanup(env.stop)

    def write_config(self, body=None):
        path = Path(self.tmp.name) / "config.yaml"
        path.write_text(body or f"group:\n  id: {GROUP_ID}\n", encoding="utf-8")
        return str(path)

    def run_cli(self, argv, client):
        """Run main() with a stub client, capturing the console mirror of the log."""
        self.stdout = io.StringIO()
        with mock.patch(
            "snyk_hybrid_project_manager.cli.SnykClient", return_value=client
        ), contextlib.redirect_stdout(self.stdout):
            return main(argv + ["--log-dir", str(self.log_dir)])

    def events(self):
        jsonl = sorted(self.log_dir.glob("*.jsonl"))[-1]
        return [json.loads(line) for line in jsonl.read_text().splitlines()]

    def events_of(self, name):
        return [e for e in self.events() if e["event"] == name]


class DryRunTests(CliTestCase):
    def test_dry_run_is_the_default_and_deletes_nothing(self):
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        code = self.run_cli(["--config", self.write_config()], client)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(client.delete_calls, [])

        duplicates = self.events_of("duplicate")
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["action"], "would_delete")
        self.assertTrue(duplicates[0]["dry_run"])

    def test_dry_run_log_names_both_the_deleted_and_the_kept_project(self):
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        self.run_cli(["--config", self.write_config()], client)

        duplicate = self.events_of("duplicate")[0]
        self.assertEqual([p["id"] for p in duplicate["deleting"]], ["scm-1"])
        self.assertEqual(duplicate["deleting"][0]["origin"], "github")
        self.assertEqual([p["id"] for p in duplicate["keeping"]], ["cli-1"])
        self.assertEqual(duplicate["keeping"][0]["origin"], "cli")
        self.assertEqual(duplicate["repo_url"], "github.com/acme/api")
        self.assertEqual(duplicate["deleting_count"], 1)
        self.assertEqual(duplicate["keeping_count"], 1)
        self.assertFalse(duplicate["coverage_drop"])
        self.assertTrue(duplicate["exclude_from_future_scans"])

    def test_both_log_files_are_written(self):
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        self.run_cli(["--config", self.write_config()], client)
        self.assertEqual(len(list(self.log_dir.glob("run-*.log"))), 1)
        self.assertEqual(len(list(self.log_dir.glob("run-*.jsonl"))), 1)
        text = next(self.log_dir.glob("run-*.log")).read_text()
        self.assertIn("DRY RUN", text)


class ExecuteTests(CliTestCase):
    def test_execute_deletes_the_scm_side_with_the_exclusion_flag(self):
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        code = self.run_cli(["--config", self.write_config(), "--execute"], client)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(client.delete_calls), 1)
        self.assertEqual(client.delete_calls[0]["ids"], ["scm-1"])
        self.assertTrue(client.delete_calls[0]["exclude"])

        deletions = self.events_of("deletion")
        self.assertEqual([d["result"] for d in deletions], ["deleted"])
        self.assertEqual(deletions[0]["kept"][0]["id"], "cli-1")

    def test_deleting_the_cli_side_never_sets_the_exclusion_flag(self):
        """The exclusion is a repo test-exclusion; it is meaningless for CLI projects."""
        config = self.write_config(f"delete: cli\norgs:\n  - {ORG_ID}\n")
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        self.run_cli(["--config", config, "--execute"], client)

        self.assertEqual(client.delete_calls[0]["ids"], ["cli-1"])
        self.assertFalse(client.delete_calls[0]["exclude"])

    def test_no_exclude_flag_is_honoured(self):
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        self.run_cli(
            ["--config", self.write_config(), "--execute", "--no-exclude-from-future-scans"],
            client,
        )
        self.assertFalse(client.delete_calls[0]["exclude"])

    def test_a_failed_deletion_is_logged_and_sets_a_non_zero_exit_code(self):
        client = FakeClient(
            [project_payload("cli-1", "cli"), project_payload("scm-1", "github")],
            delete_result={
                "deleted": [],
                "failed": [{"id": "scm-1", "name": "acme/api", "reason": "exclusion_limit_reached"}],
            },
        )
        code = self.run_cli(["--config", self.write_config(), "--execute"], client)

        self.assertEqual(code, EXIT_PARTIAL_FAILURE)
        failure = self.events_of("deletion")[0]
        self.assertEqual(failure["result"], "failed")
        self.assertEqual(failure["reason"], "exclusion_limit_reached")

    def test_a_project_the_api_ignores_is_recorded(self):
        client = FakeClient(
            [project_payload("cli-1", "cli"), project_payload("scm-1", "github")],
            delete_result={"deleted": [], "failed": []},
        )
        self.run_cli(["--config", self.write_config(), "--execute"], client)
        self.assertEqual(self.events_of("deletion")[0]["result"], "not_reported")

    def test_nothing_to_delete_makes_no_api_call(self):
        client = FakeClient([project_payload("cli-1", "cli")])
        code = self.run_cli(["--config", self.write_config(), "--execute"], client)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(client.delete_calls, [])


class SafetyTests(CliTestCase):
    def test_the_cap_blocks_an_org_and_reports_a_failure(self):
        projects = []
        for index in range(3):
            path = f"pkg{index}/package.json"
            projects.append(project_payload(f"cli-{index}", "cli", target_file=path))
            projects.append(project_payload(f"scm-{index}", "github", target_file=path))
        client = FakeClient(projects)

        code = self.run_cli(
            ["--config", self.write_config(), "--execute", "--max-deletes-per-org", "2"], client
        )

        self.assertEqual(code, EXIT_PARTIAL_FAILURE)
        self.assertEqual(client.delete_calls, [])
        actions = {e["action"] for e in self.events_of("duplicate")}
        self.assertEqual(actions, {"blocked_by_max_deletes"})

    def test_excluded_orgs_are_not_processed(self):
        config = self.write_config(
            f"group:\n  id: {GROUP_ID}\n  exclude_orgs:\n    - acme\n"
        )
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        code = self.run_cli(["--config", config, "--execute"], client)

        self.assertEqual(code, EXIT_CONFIG_ERROR)
        self.assertEqual(client.delete_calls, [])
        self.assertEqual(len(self.events_of("org_excluded")), 1)

    def test_org_filter_restricts_the_run(self):
        client = FakeClient([project_payload("cli-1", "cli"), project_payload("scm-1", "github")])
        code = self.run_cli(
            ["--config", self.write_config(), "--org", "not-in-the-group"], client
        )
        self.assertEqual(code, EXIT_CONFIG_ERROR)

    def test_projects_without_a_repo_url_are_logged_as_skipped(self):
        client = FakeClient(
            [
                project_payload("cli-1", "cli", url=None),
                project_payload("scm-1", "github"),
            ]
        )
        self.run_cli(["--config", self.write_config()], client)

        self.assertEqual(self.events_of("duplicate"), [])
        skips = self.events_of("skipped")
        self.assertEqual([s["reason"] for s in skips], ["no_repo_url"])
        self.assertEqual(skips[0]["project"]["id"], "cli-1")

    def test_snyk_code_projects_are_never_paired(self):
        client = FakeClient(
            [
                project_payload("cli-1", "cli"),
                project_payload("scm-1", "github"),
                project_payload("code-1", "github", ptype="sast", target_file=""),
            ]
        )
        self.run_cli(["--config", self.write_config(), "--execute"], client)
        self.assertEqual(client.delete_calls[0]["ids"], ["scm-1"])
        summary = self.events_of("org_summary")[0]
        self.assertEqual(summary["skips"]["non_oss_type"], 1)
        self.assertEqual(summary["type_census"]["sast"], 1)


class SkipLoggingTests(CliTestCase):
    def _client(self):
        return FakeClient(
            [
                project_payload("cli-1", "cli"),
                project_payload("scm-1", "github"),
                project_payload("code-1", "github", ptype="sast"),
                project_payload("old-1", "github", status="inactive", target_file="old.json"),
            ]
        )

    def test_bulk_skips_are_summarised_not_itemised_by_default(self):
        self.run_cli(["--config", self.write_config()], self._client())
        self.assertEqual(self.events_of("skipped"), [])
        summary = self.events_of("org_summary")[0]
        self.assertEqual(summary["skips"], {"non_oss_type": 1, "inactive": 1})

    def test_log_all_skips_itemises_every_skip(self):
        self.run_cli(["--config", self.write_config(), "--log-all-skips"], self._client())
        reasons = sorted(e["reason"] for e in self.events_of("skipped"))
        self.assertEqual(reasons, ["inactive", "non_oss_type"])


class ConfigErrorTests(CliTestCase):
    def test_a_bad_config_exits_two(self):
        path = Path(self.tmp.name) / "bad.yaml"
        path.write_text("orgs: []\n", encoding="utf-8")
        client = FakeClient([])
        self.assertEqual(self.run_cli(["--config", str(path)], client), EXIT_CONFIG_ERROR)

    def test_a_missing_token_exits_two(self):
        client = FakeClient([])
        with mock.patch.dict(os.environ, {"SNYK_TOKEN": ""}):
            self.assertEqual(self.run_cli(["--config", self.write_config()], client), EXIT_CONFIG_ERROR)


if __name__ == "__main__":
    unittest.main()
