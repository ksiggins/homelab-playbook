"""TLS verification targets must come from the declared proxy routes."""

import importlib.util
import hashlib
import json
from pathlib import Path
import unittest
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "tls_proxy_policy", ROOT / "roles/tls_automation/filter_plugins/validation.py"
)
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class ProxyPolicyTests(unittest.TestCase):
    def envelope(self, config):
        raw = json.dumps(config)
        return {"version": 1, "manifest": raw, "ingress": {
            "version": 1, "manifest_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "listen_addresses": config["bind_addresses"],
            "https_client_networks": config["client_sources"],
        }}

    def test_policy_requires_the_committed_manifest_and_verified_ingress(self):
        config = self.config()
        config["deferred_certificates"] = ["infra"]
        envelope = self.envelope(config)
        derive = lambda value: validation.committed_proxy_policy(
            json.dumps(value), config, "infra.example.com", "acme@example.com", 2001)
        self.assertEqual(validation.proxy_policy(config, "infra.example.com", "acme@example.com", 2001),
                         derive(envelope))
        for field, bad in (("manifest_sha256", "0" * 64),
                           ("listen_addresses", []), ("https_client_networks", []),
                           ("version", True)):
            altered = self.envelope(config)
            altered["ingress"][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                derive(altered)
        stale = dict(config, routes=[])
        with self.assertRaises(ValueError):
            derive(self.envelope(stale))
        with self.assertRaises(ValueError):
            derive(dict(envelope, extra=True))
        with self.assertRaises(ValueError):
            validation.committed_proxy_policy(
                json.dumps(envelope).replace('"version": 1', '"version": 1, "version": 1', 1),
                config, "infra.example.com", "acme@example.com", 2001)

    def test_coordinator_write_scope_includes_only_managed_transaction_roots(self):
        self.assertEqual(
            "/var/lib/homelab-tls /etc/caddy /var/lib/homelab-reverse-proxy",
            validation._UNITS["homelab-tls-renew.service"]["ReadWritePaths"],
        )

    def test_preflight_resolves_named_caddy_group_before_deriving_policy(self):
        tasks = yaml.safe_load((ROOT / "roles/tls_automation/tasks/preflight.yml").read_text())
        group_reads = [index for index, task in enumerate(tasks)
                       if task.get("ansible.builtin.command", {}).get("argv")
                       == ["/usr/bin/getent", "group", "caddy"]]
        policy_tasks = [index for index, task in enumerate(tasks)
                        if "tls_automation_proxy_policy" in str(task)]
        self.assertEqual(1, len(group_reads))
        self.assertEqual(1, len(policy_tasks))
        self.assertLess(group_reads[0], policy_tasks[0])

    def config(self):
        return {
            "bind_addresses": ["10.20.30.40"],
            "client_sources": ["10.20.0.0/16"],
            "routes": [
                {"hostname": "app.infra.example.com", "backend_port": 18080,
                 "certificate_name": "infra"},
                {"hostname": "unrelated.example.com", "backend_port": 18081,
                 "certificate_name": "separate"},
            ],
        }

    def test_targets_use_proxy_listener_and_only_managed_certificate_routes(self):
        result = validation.proxy_policy(self.config(), "infra.example.com", "acme@example.com", 2001)
        self.assertEqual({
            "namespace": "infra.example.com", "email": "acme@example.com", "reader_gid": 2001,
            "endpoints": [{"hostname": "app.infra.example.com", "address": "10.20.30.40", "port": 443}],
        }, result)

    def test_wrong_namespace_is_rejected_instead_of_silently_omitted(self):
        config = self.config()
        config["routes"][0]["hostname"] = "udm.example.com"
        with self.assertRaises(ValueError):
            validation.proxy_policy(config, "infra.example.com", "acme@example.com", 2001)

    def test_every_configured_listener_is_verified(self):
        config = self.config()
        config["bind_addresses"].append("fd00:20::40")
        result = validation.proxy_policy(config, "infra.example.com", "acme@example.com", 2001)
        self.assertEqual([
            {"hostname": "app.infra.example.com", "address": "10.20.30.40", "port": 443},
            {"hostname": "app.infra.example.com", "address": "fd00:20::40", "port": 443},
        ], result["endpoints"])

    def test_no_managed_route_cannot_authorize_issuance(self):
        config = self.config()
        config["routes"] = config["routes"][1:]
        with self.assertRaises(ValueError):
            validation.proxy_policy(config, "infra.example.com", "acme@example.com", 2001)

    def test_shared_route_schema_rejects_arbitrary_fields(self):
        config = self.config()
        config["routes"][0]["command"] = "unapproved"
        with self.assertRaises(ValueError):
            validation.proxy_policy(config, "infra.example.com", "acme@example.com", 2001)
