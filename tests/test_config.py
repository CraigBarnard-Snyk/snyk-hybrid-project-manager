import tempfile
import unittest

from snyk_hybrid_project_manager.config import (
    OSS_TYPES,
    ConfigError,
    load_config,
    read_token,
)

MINIMAL = """
group:
  id: 11111111-2222-3333-4444-555555555555
"""


def write(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return handle.name


class LoadConfigTests(unittest.TestCase):
    def test_minimal_config_uses_documented_defaults(self):
        config = load_config(write(MINIMAL))
        self.assertEqual(config.delete, "scm")
        self.assertEqual(config.branch_match, "ignore")
        self.assertTrue(config.exclude_from_future_scans)
        self.assertIsNone(config.max_deletes_per_org)
        self.assertEqual(config.api_url, "https://api.snyk.io")

    def test_requires_a_group_or_an_org_list(self):
        with self.assertRaisesRegex(ConfigError, "group.id or a non-empty orgs list"):
            load_config(write("log_dir: ./logs\n"))

    def test_missing_file(self):
        with self.assertRaisesRegex(ConfigError, "config file not found"):
            load_config("/nonexistent/config.yaml")

    def test_rejects_an_api_version_without_bulk_delete(self):
        with self.assertRaisesRegex(ConfigError, "predates 2024-10-15"):
            load_config(write(MINIMAL + "\napi_version: '2024-08-25'\n"))

    def test_accepts_the_minimum_api_version(self):
        self.assertEqual(
            load_config(write(MINIMAL + "\napi_version: '2024-10-15'\n")).api_version,
            "2024-10-15",
        )

    def test_rejects_unknown_keys(self):
        with self.assertRaisesRegex(ConfigError, "unknown config keys: delete_everything"):
            load_config(write(MINIMAL + "\ndelete_everything: true\n"))

    def test_rejects_an_invalid_delete_side(self):
        with self.assertRaisesRegex(ConfigError, "delete must be one of"):
            load_config(write(MINIMAL + "\ndelete: both\n"))

    def test_rejects_an_invalid_branch_match_mode(self):
        with self.assertRaisesRegex(ConfigError, "branch_match must be one of"):
            load_config(write(MINIMAL + "\nbranch_match: fuzzy\n"))

    def test_rejects_an_unknown_nested_key(self):
        with self.assertRaisesRegex(ConfigError, "unknown config keys: host_aliases"):
            load_config(write(MINIMAL + "\nhost_aliases:\n  a.example.com: b.example.com\n"))

    def test_rejects_a_duplicate_org(self):
        text = "orgs:\n  - org-1\n  - org-1\n"
        with self.assertRaisesRegex(ConfigError, "listed more than once"):
            load_config(write(text))

    def test_rejects_a_non_positive_cap(self):
        with self.assertRaisesRegex(ConfigError, "max_deletes_per_org must be a positive integer"):
            load_config(write(MINIMAL + "\nmax_deletes_per_org: 0\n"))

    def test_orgs_is_a_plain_list_of_ids(self):
        config = load_config(write("orgs:\n  - org-1\n  - org-2\n"))
        self.assertEqual(config.orgs, ("org-1", "org-2"))

    def test_a_per_org_mapping_is_rejected_with_an_explanation(self):
        with self.assertRaisesRegex(ConfigError, "One set of settings applies"):
            load_config(write("orgs:\n  - id: org-1\n    delete: cli\n"))

    def test_exclusions_match_id_slug_or_name(self):
        text = MINIMAL + "  exclude_orgs:\n    - sandbox-org\n    - org-9\n"
        config = load_config(write(text))
        self.assertTrue(config.is_excluded("org-9", None, None))
        self.assertTrue(config.is_excluded("other", "Sandbox Org", "sandbox-org"))
        self.assertFalse(config.is_excluded("org-1", "Acme", "acme"))

    def test_the_oss_type_allowlist_covers_the_common_package_managers(self):
        for project_type in ("npm", "maven", "pip", "nuget", "gomodules", "rubygems"):
            self.assertIn(project_type, OSS_TYPES)

    def test_the_oss_type_allowlist_excludes_other_snyk_products(self):
        for project_type in ("sast", "dockerfile", "deb", "terraformconfig", "k8sconfig"):
            self.assertNotIn(project_type, OSS_TYPES)


class ReadTokenTests(unittest.TestCase):
    def test_reads_the_environment(self):
        self.assertEqual(read_token({"SNYK_TOKEN": "  abc  "}), "abc")

    def test_missing_token_is_a_config_error(self):
        with self.assertRaisesRegex(ConfigError, "SNYK_TOKEN is not set"):
            read_token({})


if __name__ == "__main__":
    unittest.main()
