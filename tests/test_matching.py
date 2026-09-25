import unittest

from snyk_hybrid_project_manager.matching import (
    CLI,
    SCM,
    canonical_repo_url,
    classify_origin,
    normalise_branch,
    normalise_path,
    parse_project,
    project_path,
    select_default_branch,
)


class CanonicalRepoUrlTests(unittest.TestCase):
    def test_ssh_and_https_forms_converge(self):
        """The CLI picks up git remote (often SSH); the SCM target is HTTPS."""
        expected = "github.com/acme/api"
        for url in (
            "git@github.com:acme/api.git",
            "https://github.com/acme/api",
            "https://github.com/acme/api.git",
            "https://github.com/acme/api/",
            "ssh://git@github.com/acme/api.git",
            "http://github.com/acme/api",
            "github.com/acme/api",
        ):
            with self.subTest(url=url):
                self.assertEqual(canonical_repo_url(url), expected)

    def test_case_is_folded(self):
        self.assertEqual(
            canonical_repo_url("https://GitHub.com/Acme/API.git"), "github.com/acme/api"
        )

    def test_credentials_and_port_are_stripped(self):
        self.assertEqual(
            canonical_repo_url("https://user:token@git.example.com:8443/acme/api.git"),
            "git.example.com/acme/api",
        )

    def test_bitbucket_server_scm_segment_is_dropped(self):
        self.assertEqual(
            canonical_repo_url("https://bitbucket.example.com/scm/proj/api.git"),
            "bitbucket.example.com/proj/api",
        )
        self.assertEqual(
            canonical_repo_url("ssh://git@bitbucket.example.com:7999/proj/api.git"),
            "bitbucket.example.com/proj/api",
        )

    def test_azure_repos_git_segment_is_dropped(self):
        self.assertEqual(
            canonical_repo_url("https://dev.azure.com/acme/project/_git/api"),
            "dev.azure.com/acme/project/api",
        )

    def test_azure_devops_ssh_and_https_forms_converge(self):
        expected = "dev.azure.com/acme/project/api"
        for url in (
            "https://dev.azure.com/acme/project/_git/api",
            "git@ssh.dev.azure.com:v3/acme/project/api",
        ):
            with self.subTest(url=url):
                self.assertEqual(canonical_repo_url(url), expected)

    def test_github_ssh_alias_host_is_folded(self):
        self.assertEqual(
            canonical_repo_url("git@ssh.github.com:acme/api.git"), "github.com/acme/api"
        )

    def test_a_v3_path_segment_is_kept_on_non_azure_hosts(self):
        self.assertEqual(
            canonical_repo_url("https://github.com/v3/api"), "github.com/v3/api"
        )

    def test_missing_or_unusable_urls_return_none(self):
        for url in (None, "", "   ", "https://github.com", "https://github.com/"):
            with self.subTest(url=url):
                self.assertIsNone(canonical_repo_url(url))


class NormalisationTests(unittest.TestCase):
    def test_path_normalisation(self):
        self.assertEqual(normalise_path("./sub/dir/pom.xml"), "sub/dir/pom.xml")
        self.assertEqual(normalise_path("/sub//dir/pom.xml"), "sub/dir/pom.xml")
        self.assertEqual(normalise_path("sub\\dir\\pom.xml"), "sub/dir/pom.xml")
        self.assertEqual(normalise_path(None), "")

    def test_path_case_is_preserved(self):
        self.assertEqual(normalise_path("./Sub/Pom.xml"), "Sub/Pom.xml")

    def test_branch_normalisation(self):
        self.assertEqual(normalise_branch("  Main "), "main")
        self.assertEqual(normalise_branch(None), "")


class ClassifyOriginTests(unittest.TestCase):
    def setUp(self):
        self.cli = {"cli"}
        self.scm = {"github", "gitlab", "azure-repos"}

    def test_sides(self):
        self.assertEqual(classify_origin("cli", self.cli, self.scm), CLI)
        self.assertEqual(classify_origin("GitHub", self.cli, self.scm), SCM)

    def test_unclassified_origins_are_none(self):
        for origin in ("api", "docker", "", None, "unknown"):
            with self.subTest(origin=origin):
                self.assertIsNone(classify_origin(origin, self.cli, self.scm))


def project_payload(**overrides):
    payload = {
        "id": "11111111-1111-1111-1111-111111111111",
        "type": "project",
        "attributes": {
            "name": "acme/api:sub/package.json",
            "origin": "github",
            "type": "npm",
            "target_file": "sub/package.json",
            "target_reference": "main",
            "status": "active",
            "created": "2024-05-01T10:00:00Z",
        },
        "relationships": {
            "target": {
                "data": {
                    "id": "22222222-2222-2222-2222-222222222222",
                    "type": "target",
                    "attributes": {
                        "url": "https://github.com/acme/api",
                        "display_name": "acme/api",
                    },
                }
            }
        },
    }
    payload["attributes"].update(overrides.pop("attributes", {}))
    payload.update(overrides)
    return payload


class ParseProjectTests(unittest.TestCase):
    def test_expanded_target_supplies_the_repo_url(self):
        project = parse_project(project_payload())
        self.assertEqual(project.target_url, "https://github.com/acme/api")
        self.assertEqual(project.target_display_name, "acme/api")
        self.assertEqual(project.type, "npm")
        self.assertTrue(project.is_active)

    def test_unexpanded_target_has_no_url(self):
        payload = project_payload()
        payload["relationships"]["target"]["data"].pop("attributes")
        project = parse_project(payload)
        self.assertIsNone(project.target_url)
        self.assertEqual(project.target_id, "22222222-2222-2222-2222-222222222222")

    def test_missing_relationships_are_tolerated(self):
        payload = project_payload()
        payload.pop("relationships")
        project = parse_project(payload)
        self.assertIsNone(project.target_url)
        self.assertIsNone(project.target_id)

    def test_inactive_status(self):
        project = parse_project(project_payload(attributes={"status": "inactive"}))
        self.assertFalse(project.is_active)

    def test_path_falls_back_to_the_name_when_target_file_is_empty(self):
        project = parse_project(project_payload(attributes={"target_file": ""}))
        self.assertEqual(project_path(project), "sub/package.json")

    def test_path_is_empty_for_a_root_manifest_with_no_target_file(self):
        project = parse_project(
            project_payload(attributes={"target_file": "", "name": "acme/api"})
        )
        self.assertEqual(project_path(project), "")


class SelectDefaultBranchTests(unittest.TestCase):
    def test_prefers_a_configured_default_branch(self):
        branches = [("release", 9, "2024-01-01"), ("main", 1, "2024-02-01")]
        self.assertEqual(select_default_branch(branches, ("main", "master")), "main")

    def test_falls_back_to_the_busiest_branch(self):
        branches = [("develop", 2, "2024-02-01"), ("release", 5, "2024-03-01")]
        self.assertEqual(select_default_branch(branches, ("main", "master")), "release")

    def test_ties_break_on_earliest_created_then_name(self):
        branches = [("b", 3, "2024-05-01"), ("a", 3, "2024-01-01")]
        self.assertEqual(select_default_branch(branches, ()), "a")

    def test_empty_input(self):
        self.assertIsNone(select_default_branch([], ("main",)))


if __name__ == "__main__":
    unittest.main()
