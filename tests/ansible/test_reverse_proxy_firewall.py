"""Private HTTPS contributes exact TCP rules to both baseline operations."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProxyFirewallTests(unittest.TestCase):
    def builders(self):
        for path, name in (
            (
                "roles/security_baseline/filter_plugins/platform_controls.py",
                "security_baseline_firewall_rules",
            ),
            (
                "roles/os_baseline_verify/filter_plugins/controls.py",
                "os_baseline_verify_firewall_rules",
            ),
        ):
            spec = importlib.util.spec_from_file_location(name, ROOT / path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            yield getattr(module, name)

    def payload(self, **updates):
        values = dict(
            management_sources=["10.0.0.0/24"],
            services=[dict(service="dns", sources=["10.1.0.0/24"])],
            reverse_proxy_routes=[
                dict(
                    hostname="app.example.test",
                    backend_port=8080,
                    certificate_name="app",
                )
            ],
            reverse_proxy_sources=["10.2.0.0/24", "fd00:1::/64"],
        )
        return dict(values, **updates)

    def test_https_sources_are_distinct_from_ssh_and_preserve_other_services(self):
        expected = [
            'rule family="ipv4" source address="10.0.0.0/24" port port="22" protocol="tcp" accept',
            'rule family="ipv4" source address="10.1.0.0/24" service name="dns" accept',
            'rule family="ipv4" source address="10.2.0.0/24" port port="443" protocol="tcp" accept',
            'rule family="ipv6" source address="fd00:1::/64" port port="443" protocol="tcp" accept',
        ]
        for build in self.builders():
            with self.subTest(builder=build.__name__):
                self.assertEqual(expected, build(self.payload()))

    def test_removing_final_route_removes_https_allowance(self):
        for build in self.builders():
            rules = build(self.payload(reverse_proxy_routes=[]))
            self.assertEqual(2, len(rules))
            self.assertFalse(any("443" in rule for rule in rules))

    def test_admin_only_proxy_allows_empty_client_sources(self):
        for build in self.builders():
            with self.subTest(builder=build.__name__):
                rules = build(
                    self.payload(reverse_proxy_routes=[], reverse_proxy_sources=[])
                )
                self.assertEqual(2, len(rules))
                self.assertFalse(any("443" in rule for rule in rules))

    def test_active_proxy_requires_private_explicit_client_sources(self):
        for build in self.builders():
            for sources in ([], ["0.0.0.0/0"], ["203.0.113.0/24"], "10.2.0.0/24"):
                with self.subTest(builder=build.__name__, sources=sources):
                    with self.assertRaises(ValueError):
                        build(self.payload(reverse_proxy_sources=sources))

    def test_route_list_cannot_be_a_boolean_or_string(self):
        for build in self.builders():
            for routes in (True, "enabled", {}):
                with self.subTest(builder=build.__name__, routes=routes):
                    with self.assertRaises(ValueError):
                        build(self.payload(reverse_proxy_routes=routes))
