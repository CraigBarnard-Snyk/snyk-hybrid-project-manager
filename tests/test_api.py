import json
import unittest

import requests

from snyk_hybrid_project_manager.api import MAX_BULK_DELETE, SnykApiError, SnykClient, chunked


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text if text is not None else json.dumps(payload or {})
        self.content = self.text.encode()

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Replays a queued list of responses (or exceptions) and records calls."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}

    def request(self, method, url, params=None, json=None, headers=None, timeout=None):
        self.calls.append(
            {"method": method, "url": url, "params": params, "json": json, "timeout": timeout}
        )
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client_for(responses, **kwargs):
    slept = []
    session = FakeSession(responses)
    client = SnykClient(
        base_url="https://api.snyk.io",
        token="secret",
        api_version="2026-03-25",
        session=session,
        sleep=slept.append,
        **kwargs,
    )
    return client, session, slept


class UrlTests(unittest.TestCase):
    def test_rest_prefix_is_added(self):
        client, _, _ = client_for([])
        self.assertEqual(client._url("/orgs/1/projects"), "https://api.snyk.io/rest/orgs/1/projects")

    def test_absolute_next_links_are_left_alone(self):
        client, _, _ = client_for([])
        self.assertEqual(client._url("https://api.eu.snyk.io/rest/x"), "https://api.eu.snyk.io/rest/x")

    def test_a_next_link_that_already_has_the_prefix_is_not_doubled(self):
        client, _, _ = client_for([])
        self.assertEqual(client._url("/rest/orgs/1/projects"), "https://api.snyk.io/rest/orgs/1/projects")

    def test_auth_header_scheme(self):
        client, session, _ = client_for([])
        self.assertEqual(session.headers["Authorization"], "token secret")
        bearer, bearer_session, _ = client_for([], auth_scheme="bearer")
        self.assertEqual(bearer_session.headers["Authorization"], "Bearer secret")


class RetryTests(unittest.TestCase):
    def test_429_is_retried_and_honours_retry_after(self):
        responses = [
            FakeResponse(429, {}, {"Retry-After": "7"}),
            FakeResponse(200, {"data": []}),
        ]
        client, session, slept = client_for(responses)
        client._request("GET", "/orgs/1/projects")
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(slept, [7.0])

    def test_5xx_is_retried_with_backoff(self):
        responses = [FakeResponse(503, {}), FakeResponse(200, {"data": []})]
        client, session, slept = client_for(responses)
        client._request("GET", "/orgs/1/projects")
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(len(slept), 1)
        self.assertGreater(slept[0], 0)

    def test_transport_errors_are_retried(self):
        responses = [requests.ConnectionError("boom"), FakeResponse(200, {"data": []})]
        client, session, _ = client_for(responses)
        client._request("GET", "/orgs/1/projects")
        self.assertEqual(len(session.calls), 2)

    def test_retries_are_bounded(self):
        client, session, _ = client_for([FakeResponse(500, {})] * 3, max_retries=3)
        with self.assertRaisesRegex(SnykApiError, "failed after 3 attempts"):
            client._request("GET", "/orgs/1/projects")
        self.assertEqual(len(session.calls), 3)

    def test_client_errors_are_not_retried(self):
        client, session, _ = client_for([FakeResponse(403, {}, text="forbidden")])
        with self.assertRaises(SnykApiError) as ctx:
            client._request("GET", "/orgs/1/projects")
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(len(session.calls), 1)


class PaginationTests(unittest.TestCase):
    def test_follows_next_links_until_exhausted(self):
        responses = [
            FakeResponse(200, {"data": [{"id": "1"}], "links": {"next": "/rest/orgs/1/projects?x=2"}}),
            FakeResponse(200, {"data": [{"id": "2"}], "links": {}}),
        ]
        client, session, _ = client_for(responses)
        items = list(client.list_projects("1"))
        self.assertEqual([i["id"] for i in items], ["1", "2"])
        self.assertEqual(session.calls[0]["params"], {"limit": 100, "expand": "target", "version": "2026-03-25"})
        # The next link already carries its own cursor and version.
        self.assertIsNone(session.calls[1]["params"])

    def test_next_link_object_form_is_supported(self):
        responses = [
            FakeResponse(200, {"data": [{"id": "1"}], "links": {"next": {"href": "/rest/next"}}}),
            FakeResponse(200, {"data": [{"id": "2"}]}),
        ]
        client, _, _ = client_for(responses)
        self.assertEqual([i["id"] for i in client.list_projects("1")], ["1", "2"])

    def test_a_repeating_cursor_does_not_loop_forever(self):
        page = {"data": [{"id": "1"}], "links": {"next": "/rest/same"}}
        client, _, _ = client_for([FakeResponse(200, page), FakeResponse(200, page)])
        self.assertEqual(len(list(client.list_projects("1"))), 2)


class BulkDeleteTests(unittest.TestCase):
    def test_request_body_shape(self):
        responses = [FakeResponse(200, {"meta": {"deleted": [{"id": "p1", "name": "n"}], "failed": []}})]
        client, session, _ = client_for(responses)
        result = client.bulk_delete_projects("org-1", ["p1"], exclude_from_future_scans=True)

        call = session.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/rest/orgs/org-1/projects/bulk-delete"))
        self.assertEqual(call["params"], {"version": "2026-03-25"})
        self.assertEqual(
            call["json"],
            {
                "data": [{"type": "project", "id": "p1"}],
                "meta": {"exclude_from_future_scans": True},
            },
        )
        self.assertEqual(result["deleted"], [{"id": "p1", "name": "n"}])

    def test_partial_success_returns_both_lists(self):
        payload = {
            "meta": {
                "deleted": [{"id": "p1", "name": "a"}],
                "failed": [{"id": "p2", "name": "b", "reason": "exclusion_limit_reached"}],
            }
        }
        client, _, _ = client_for([FakeResponse(200, payload)])
        result = client.bulk_delete_projects("org-1", ["p1", "p2"], False)
        self.assertEqual(len(result["deleted"]), 1)
        self.assertEqual(result["failed"][0]["reason"], "exclusion_limit_reached")

    def test_empty_input_makes_no_request(self):
        client, session, _ = client_for([])
        self.assertEqual(client.bulk_delete_projects("org-1", [], True), {"deleted": [], "failed": []})
        self.assertEqual(session.calls, [])

    def test_batches_larger_than_the_api_limit_are_rejected(self):
        client, _, _ = client_for([])
        with self.assertRaisesRegex(ValueError, "at most 100 projects"):
            client.bulk_delete_projects("org-1", [str(i) for i in range(101)], True)


class ChunkedTests(unittest.TestCase):
    def test_splits_on_the_api_limit(self):
        batches = list(chunked([str(i) for i in range(250)], MAX_BULK_DELETE))
        self.assertEqual([len(b) for b in batches], [100, 100, 50])

    def test_empty_input(self):
        self.assertEqual(list(chunked([])), [])


if __name__ == "__main__":
    unittest.main()
