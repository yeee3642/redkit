"""Framework smoke tests — pure stdlib unittest, no pytest required.

Run with:  python -m unittest discover -s tests
"""
import unittest
from pathlib import Path

from redkit import modules
from redkit.core import registry
from redkit.core.engagement import Engagement
from redkit.core.module import Module, Option, Result


class TestModuleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        modules.load_all()

    def test_modules_discovered(self):
        mods = registry.all_modules()
        self.assertTrue(mods, "no modules were registered")

    def test_every_module_is_valid(self):
        for name, cls in registry.all_modules().items():
            with self.subTest(module=name):
                self.assertTrue(issubclass(cls, Module))
                self.assertEqual(cls.name, name)
                self.assertIn(cls.phase, registry.PHASES)
                self.assertIsInstance(cls.description, str)
                self.assertTrue(cls.description)
                for opt in cls.options:
                    self.assertIsInstance(opt, Option)
                # run() must be overridden
                self.assertIsNot(cls.run, Module.run)

    def test_option_resolution_required(self):
        class Dummy(Module):
            name = "misc.dummy"
            phase = "misc"
            options = [Option("target", required=True), Option("n", default=5)]

        with self.assertRaises(ValueError):
            Dummy.resolve_options({})  # missing required
        resolved = Dummy.resolve_options({"target": "x"})
        self.assertEqual(resolved["n"], 5)
        # int coercion from string
        self.assertEqual(Dummy.resolve_options({"target": "x", "n": "9"})["n"], 9)
        # unknown option rejected
        with self.assertRaises(ValueError):
            Dummy.resolve_options({"target": "x", "bogus": 1})


class TestEngagementStore(unittest.TestCase):
    def test_roundtrip(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "engagement.json"
            eng = Engagement.load_or_create(path)
            eng.add_service("10.0.0.1", 445, "tcp", service="smb")
            eng.add_cred("smb", host="10.0.0.1", username="admin", password="admin")
            eng.add_finding("Default creds", severity="high", host="10.0.0.1")
            eng.save()

            reopened = Engagement.load_or_create(path)
            self.assertIn("10.0.0.1", reopened.hosts())
            self.assertEqual(len(reopened.data["creds"]), 1)
            self.assertEqual(reopened.data["findings"][0]["id"], "F-001")
            self.assertEqual(len(reopened.open_ports()), 1)


class TestResult(unittest.TestCase):
    def test_defaults(self):
        r = Result()
        self.assertTrue(r.ok)
        self.assertEqual(r.data, {})
        self.assertEqual(r.artifacts, [])


class TestRating(unittest.TestCase):
    def test_cvss_known_scores(self):
        from redkit.core import rating

        self.assertEqual(rating.cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H"), (9.8, "critical"))
        self.assertEqual(rating.cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N"), (7.5, "high"))
        self.assertEqual(rating.cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), (6.1, "medium"))
        self.assertEqual(rating.cvss_base("garbage"), (0.0, "none"))

    def test_classify(self):
        from redkit.core import rating

        self.assertEqual(rating.classify("SQL injection in id"), "sqli")
        self.assertEqual(rating.classify("Reflected XSS: q"), "xss")
        self.assertEqual(rating.classify("Exposed sensitive file: /.git/config"), "git-exposure")
        self.assertEqual(rating.classify("JWT HMAC secret cracked"), "jwt-weak-secret")

    def test_enrich_adds_poc_rating_and_submittable(self):
        from redkit.core import rating

        f = {
            "title": "SQL injection (error-based) in parameter 'id'",
            "severity": "critical",
            "evidence": "param='id' payload='",
            "host": "h",
        }
        rating.enrich_finding(f, target_url="http://h/item?id=1")
        self.assertEqual(f["cvss_score"], 9.8)
        self.assertEqual(f["cwe"], "CWE-89")
        self.assertTrue(f["submittable"])
        self.assertIn("curl", f["poc"])

        # a low-confidence heuristic finding must not be auto-submittable
        g = {"title": "Suspected SSRF via 'url' [low-confidence]", "evidence": "param=url", "host": "h"}
        rating.enrich_finding(g, target_url="http://h/f?url=x")
        self.assertFalse(g["submittable"])


if __name__ == "__main__":
    unittest.main()
