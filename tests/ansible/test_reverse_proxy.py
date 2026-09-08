"""Independent public input contract for the shared HTTPS proxy."""

import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReverseProxyInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "roles/reverse_proxy/filter_plugins/proxy.py"
        spec = importlib.util.spec_from_file_location("reverse_proxy_filter", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def fixture(self):
        return {"bind_addresses": ["10.0.0.2"], "client_sources": ["10.0.0.0/24"],
                "routes": [{"hostname": "app.example.test", "backend_port": 8080,
                            "certificate_name": "app"}]}

    def test_empty_routes_need_no_ingress(self):
        self.assertEqual(self.module.validate({"bind_addresses": [], "client_sources": [], "routes": []}),
                         {"bind_addresses": [], "client_sources": [], "routes": []})

    def test_canonical_values_without_mutating_input(self):
        value = self.fixture()
        value["bind_addresses"] += ["fd00:0:0::2"]
        value["client_sources"] += ["fd00::/64"]
        value["routes"][0]["hostname"] = "APP.Example.test"
        original = copy.deepcopy(value)
        result = self.module.validate(value)
        self.assertEqual(result["bind_addresses"], ["10.0.0.2", "fd00::2"])
        self.assertEqual(result["routes"][0]["hostname"], "app.example.test")
        self.assertEqual(value, original)

    def test_route_cannot_inject_config_or_path(self):
        for field, values in {"hostname": ["app.example.test\nadmin :2019", "*.example.test", "a/b", "localhost", "a..test", "-a.test", "a.test:443", "https://a.test", "10.0.0.2"],
                              "certificate_name": ["../app", ".", "a/b", "app\ntls internal", "app key", "-app"]}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    data = self.fixture()
                    data["routes"][0][field] = value
                    with self.assertRaises(ValueError):
                        self.module.validate(data)

    def test_ports_are_unprivileged_integers(self):
        for value in (True, False, 443, 1023, 65536, "8080", 8080.0, None):
            data = self.fixture()
            data["routes"][0]["backend_port"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.module.validate(data)
        for value in (1024, 65535):
            data = self.fixture()
            data["routes"][0]["backend_port"] = value
            self.assertEqual(self.module.validate(data)["routes"][0]["backend_port"], value)

    def test_tagged_ansible_integer_is_accepted_without_accepting_booleans(self):
        class TaggedInteger(int):
            pass

        data = self.fixture()
        data["routes"][0]["backend_port"] = TaggedInteger(8080)
        self.assertEqual(self.module.validate(data)["routes"][0]["backend_port"], 8080)

    def test_duplicate_hostname_is_case_insensitive(self):
        data = self.fixture()
        data["routes"].append(dict(data["routes"][0], hostname="APP.EXAMPLE.TEST"))
        with self.assertRaises(ValueError):
            self.module.validate(data)

    def test_only_explicit_private_addresses_and_networks(self):
        for field, values in {"bind_addresses": ["0.0.0.0", "::", "127.0.0.1", "169.254.1.1", "192.0.2.2", "8.8.8.8", "fe80::1", "fd00::1%eth0", "10.0.0.2/24"],
                              "client_sources": ["0.0.0.0/0", "::/0", "127.0.0.0/8", "192.0.2.0/24", "10.0.0.1/24", "10.0.0.2", "fe80::/64"]}.items():
            for value in values:
                data = self.fixture()
                data[field] = [value]
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.module.validate(data)

    def test_schema_rejects_unknown_fields_and_wrong_types(self):
        for change in ({"extra": True}, {"routes": {}}, {"routes": [None]},
                       {"bind_addresses": "10.0.0.2"}, {"client_sources": []},
                       {"bind_addresses": []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.module.validate(dict(self.fixture(), **change))
        data = self.fixture()
        data["routes"][0]["upstream"] = "remote:8080"
        with self.assertRaises(ValueError):
            self.module.validate(data)


if __name__ == "__main__":
    unittest.main()
