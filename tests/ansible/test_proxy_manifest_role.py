"""Ingress verification must precede authorization of desired route activation."""

from pathlib import Path
import hashlib
import json
import unittest

from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template
import yaml


ROLE = Path(__file__).resolve().parents[2] / "roles/reverse_proxy"


class ManifestRoleTests(unittest.TestCase):
    def test_trust_installation_checks_this_runs_own_bytes_before_activation(self):
        tasks = yaml.safe_load((ROLE / "tasks/configure.yml").read_text())
        install = next(i for i, task in enumerate(tasks)
                       if task.get("ansible.builtin.command", {}).get("argv")
                       == ["/usr/local/libexec/homelab-reverse-proxy", "install-trust"])
        verify = next(i for i, task in enumerate(tasks)
                      if task["name"] == "Require this deployment's exact immutable trust contents")
        self.assertLess(install, verify)
        declared = "synthetic certificate contents"
        observed = {"exists": True, "isreg": True, "islnk": False, "uid": 0,
                    "gr_name": "caddy", "nlink": 1, "mode": "0640",
                    "checksum": hashlib.sha256(declared.encode()).hexdigest()}
        def accepted():
            templar = Templar(loader=DataLoader(), variables={
                "item": {"stat": observed, "item": {"value": declared}}})
            return all(templar.template(trust_as_template("{{ " + expression + " }}"))
                       for expression in tasks[verify]["ansible.builtin.assert"]["that"])
        self.assertTrue(accepted())
        observed["checksum"] = hashlib.sha256(b"other concurrent declaration").hexdigest()
        self.assertFalse(accepted())

    def test_ansible_serialization_produces_json_with_matching_ingress_hash(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        config = {"bind_addresses": [], "client_sources": [], "routes": [],
                  "deferred_certificates": []}
        values = {"reverse_proxy_config": config}
        outputs = {}
        for task in tasks:
            facts = task.get("ansible.builtin.set_fact", {})
            if "reverse_proxy_manifest_bytes" in facts:
                values["reverse_proxy_manifest_bytes"] = Templar(
                    loader=DataLoader(), variables=values,
                ).template(trust_as_template(facts["reverse_proxy_manifest_bytes"]))
            copy = task.get("ansible.builtin.copy", {})
            if "content" in copy:
                outputs[Path(copy["dest"]).name] = Templar(
                    loader=DataLoader(), variables=values,
                ).template(trust_as_template(copy["content"]))
        raw = outputs["desired.candidate.json"]
        self.assertEqual(config, json.loads(raw))
        self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(),
                         json.loads(outputs["ingress.candidate.json"])["manifest_sha256"])

    def test_verified_ingress_precedes_manifest_activation(self):
        tasks = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
        verification = next(i for i, task in enumerate(tasks)
                            if task.get("ansible.builtin.include_role", {}).get("name") == "os_baseline_verify")
        stamps = [i for i, task in enumerate(tasks)
                  if task.get("ansible.builtin.copy", {}).get("dest")
                  == "/var/lib/homelab-reverse-proxy/ingress.candidate.json"]
        activations = [i for i, task in enumerate(tasks)
                       if task.get("ansible.builtin.command", {}).get("argv")
                       == ["/usr/local/libexec/homelab-reverse-proxy", "apply-desired"]]
        self.assertEqual(1, len(stamps))
        self.assertEqual(1, len(activations))
        self.assertLess(verification, stamps[0])
        self.assertLess(stamps[0], activations[0])

    def test_role_does_not_overwrite_committed_manifest_authority(self):
        for source in (ROLE / "tasks").glob("*.yml"):
            tasks = yaml.safe_load(source.read_text())
            for task in tasks:
                for module in ("ansible.builtin.copy", "ansible.builtin.template"):
                    self.assertNotEqual(
                        "/var/lib/homelab-reverse-proxy/desired.json",
                        task.get(module, {}).get("dest"),
                        source.name,
                    )
