from __future__ import annotations
import importlib.util, unittest
from pathlib import Path
P=Path(__file__).resolve().parents[1]/"scripts"/"discover_providers.py"
S=importlib.util.spec_from_file_location("discover_providers",P)
M=importlib.util.module_from_spec(S); assert S and S.loader; S.loader.exec_module(M)

class DiscoveryTests(unittest.TestCase):
    def test_external_links(self):
        body='<a href="/x">internal</a><a href="https://AlphaVPS.example/order?ref=x">Visit site</a><a href="https://github.com/x/y">GitHub</a>'
        found=M.extract_external_domains("https://directory.example/providers",body,set(M.DEFAULT_EXCLUDED_DOMAINS))
        self.assertEqual(set(found),{"alphavps.example"})
    def test_known_subdomain(self):
        known=M.known_domains([{"domains":["known.example"]}])
        self.assertTrue(M.is_known("shop.known.example",known))
        self.assertFalse(M.is_known("new.example",known))
    def test_promoted_domain_drops_from_backlog(self):
        prev=[{"domain":"old.example","status":"discovered","sources":[],"directory_signals":[],"source_links":[],"labels":[]},{"domain":"known.example","status":"discovered","sources":[],"directory_signals":[],"source_links":[],"labels":[]}]
        records,errors=M.discover({"sources":[]},[{"domains":["known.example"]}],prev)
        self.assertEqual(errors,[]); self.assertEqual([x["domain"] for x in records],["old.example"])

if __name__=="__main__": unittest.main()
