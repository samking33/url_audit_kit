import unittest
from unittest.mock import patch

from bs4 import BeautifulSoup as RealBeautifulSoup
from bs4 import FeatureNotFound

import url_audit.utils as utils


class FakeResponse:
    def __init__(self, url: str, html: str):
        self.url = url
        self.status_code = 200
        self.headers = {"content-type": "text/html"}
        self.content = html.encode("utf-8")
        self.text = html


class UtilsTests(unittest.TestCase):
    def setUp(self) -> None:
        utils._FETCH_CACHE.clear()
        utils._FETCH_DIAGNOSTICS.clear()

    def test_normalize_url_adds_https_and_normalizes_host(self):
        normalized = utils.normalize_url("Example.COM/login?x=1")
        self.assertEqual(normalized, "https://example.com/login?x=1")

    def test_normalize_url_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            utils.normalize_url("ftp://example.com")

    def test_fetch_falls_back_to_html_parser_when_lxml_unavailable(self):
        html = "<html><head><title>ok</title></head><body>hello</body></html>"

        def fake_get(*_args, **_kwargs):
            return FakeResponse("https://example.com/", html)

        def fake_bs4(content, parser):
            if parser == "lxml":
                raise FeatureNotFound("lxml unavailable")
            return RealBeautifulSoup(content, "html.parser")

        with patch("url_audit.utils.requests.get", side_effect=fake_get), patch(
            "url_audit.utils.BeautifulSoup", side_effect=fake_bs4
        ):
            response, fetched_html, soup = utils.fetch("example.com")

        self.assertIsNotNone(response)
        self.assertEqual(fetched_html, html)
        self.assertIsNotNone(soup)
        self.assertEqual((soup.title.string or "").strip(), "ok")

        diagnostics = utils.get_fetch_diagnostics("https://example.com/")
        self.assertTrue(diagnostics.get("success"))
        self.assertEqual(diagnostics.get("parser"), "html.parser")


if __name__ == "__main__":
    unittest.main()
