"""Trust names are immutable even across interrupted or concurrent installs."""
import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest import mock

from test_reverse_proxy_activation import ActivationFixture
from test_proxy_manifest_runtime import manifest_module

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tls'))
from cert_fixtures import EphemeralCA
from cryptography.hazmat.primitives import serialization


class TrustFixture(ActivationFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pem_a = EphemeralCA('Trust fixture A').certificate.public_bytes(serialization.Encoding.PEM).decode()
        cls.pem_b = EphemeralCA('Trust fixture B').certificate.public_bytes(serialization.Encoding.PEM).decode()

    def setUp(self):
        super().setUp()
        self.manifest_runtime = manifest_module()
        sys.modules['proxy_manifest'] = self.manifest_runtime
        self.trust_root = self.root / 'etc/caddy/trust'
        self.trust_root.mkdir(mode=0o750)
        self.source = self.state / 'trust.candidate.json'

    def trust_candidate(self, value):
        self.write(self.source, json.dumps(value), 0o600)


class TrustInstallTests(TrustFixture):
    def test_existing_name_rejects_replacement_and_preserves_original_inode(self):
        self.trust_candidate({'device': self.pem_a})
        self.assertEqual('changed', self.activation.install_trust())
        target = self.trust_root / 'device.pem'
        original = target.stat()
        self.assertEqual(self.pem_a, target.read_text())
        self.assertEqual(0o640, stat.S_IMODE(original.st_mode))
        self.assertEqual(1, original.st_nlink)
        self.assertEqual('unchanged', self.activation.install_trust())
        self.trust_candidate({'device': self.pem_b})
        with self.assertRaises((ValueError, self.module.ActivationError)):
            self.activation.install_trust()
        self.assertEqual(original.st_ino, target.stat().st_ino)
        self.assertEqual(self.pem_a, target.read_text())

    def test_all_inputs_are_validated_before_any_new_anchor(self):
        for invalid in [{'../escape': self.pem_a}, {'device': 'not a PEM certificate'},
                        {'device': 1}, {'device': '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n'},
                        {'device': self.pem_a + 'unparsed suffix'}, [],
                        {'device': self.pem_a * 1000}]:
            with self.subTest(value_type=type(invalid).__name__):
                self.trust_candidate(invalid)
                with self.assertRaises((ValueError, self.module.ActivationError)):
                    self.activation.install_trust()
                self.assertEqual([], list(self.trust_root.iterdir()))

    def test_empty_mapping_is_unchanged_and_never_deletes_anchors(self):
        self.trust_candidate({'device': self.pem_a})
        self.activation.install_trust()
        self.trust_candidate({})
        self.assertEqual('unchanged', self.activation.install_trust())
        self.assertEqual(self.pem_a, (self.trust_root / 'device.pem').read_text())

    def test_unsafe_candidate_root_and_existing_anchor_metadata_are_rejected(self):
        self.trust_candidate({'device': self.pem_a})
        self.source.chmod(0o644)
        with self.assertRaises(self.module.ActivationError):
            self.activation.install_trust()
        self.source.chmod(0o600)
        self.trust_root.chmod(0o770)
        with self.assertRaises(self.module.ActivationError):
            self.activation.install_trust()
        self.trust_root.chmod(0o750)
        target = self.trust_root / 'device.pem'
        target.symlink_to(self.source)
        with self.assertRaises(self.module.ActivationError):
            self.activation.install_trust()
        target.unlink()
        self.write(target, self.pem_a, 0o644)
        with self.assertRaises(self.module.ActivationError):
            self.activation.install_trust()
        target.chmod(0o640)
        os.link(target, self.trust_root / 'unrelated-hardlink')
        with self.assertRaises(self.module.ActivationError):
            self.activation.install_trust()

    def test_extended_or_default_acl_is_rejected(self):
        self.trust_candidate({'device': self.pem_a})
        original = getattr(os, 'listxattr', lambda path, **kwargs: [])
        for attribute in ('system.posix_acl_access', 'system.posix_acl_default'):
            def attributes(path, **kwargs):
                return [attribute] if Path(path) == self.trust_root else original(path, **kwargs)
            with self.subTest(attribute=attribute), mock.patch('os.listxattr', side_effect=attributes, create=True):
                with self.assertRaises((ValueError, self.module.ActivationError)):
                    self.activation.install_trust()
        self.assertEqual([], list(self.trust_root.iterdir()))

    def test_duplicate_names_are_rejected_before_installation(self):
        self.write(self.source, '{"device":' + json.dumps(self.pem_a) + ',"device":' + json.dumps(self.pem_b) + '}', 0o600)
        with self.assertRaises(ValueError):
            self.activation.install_trust()
        self.assertEqual([], list(self.trust_root.iterdir()))

    def test_atomic_no_replace_preserves_a_file_created_at_publication_boundary(self):
        self.trust_candidate({'device': self.pem_a})
        target = self.trust_root / 'device.pem'
        original = os.link
        def contention(source, destination, **kwargs):
            self.write(target, self.pem_b)
            return original(source, destination, **kwargs)
        with mock.patch('os.link', side_effect=contention), self.assertRaises((ValueError, self.module.ActivationError)):
            self.activation.install_trust()
        self.assertEqual(self.pem_b, target.read_text())
        self.assertEqual(1, target.stat().st_nlink)


class TrustRecoveryTests(TrustFixture):
    def test_retry_recovers_interruption_after_link_without_overwriting_winner(self):
        self.trust_candidate({'device': self.pem_a})
        original = os.link
        def interrupted(source, destination, **kwargs):
            original(source, destination, **kwargs)
            raise KeyboardInterrupt()
        with mock.patch('os.link', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.activation.install_trust()
        self.assertEqual(self.pem_a, (self.trust_root / 'device.pem').read_text())
        self.trust_candidate({'device': self.pem_b})
        with self.assertRaises((ValueError, self.module.ActivationError)):
            self.activation.install_trust()
        self.assertEqual(['device.pem'], [path.name for path in self.trust_root.iterdir()])
        self.assertEqual(1, (self.trust_root / 'device.pem').stat().st_nlink)
        self.assertEqual(self.pem_a, (self.trust_root / 'device.pem').read_text())

    def test_abandoned_partial_stage_is_cleaned_without_touching_other_files(self):
        self.trust_candidate({'device': self.pem_a})
        stage = self.trust_root / ('.trust-stage-device-' + 'a' * 32)
        self.write(stage, 'partial bytes', 0o600)
        unrelated = self.trust_root / '.unrelated'
        self.write(unrelated, 'keep', 0o600)
        self.assertEqual('changed', self.activation.install_trust())
        self.assertFalse(stage.exists())
        self.assertEqual('keep', unrelated.read_text())


class TrustConcurrencyTests(TrustFixture):
    def test_different_concurrent_bundles_have_one_winner_and_one_failure(self):
        self.trust_candidate({'device': self.pem_a})
        context = multiprocessing.get_context('fork')
        first_parent, first_child = context.Pipe()
        second_parent, second_child = context.Pipe()
        self.addCleanup(first_parent.close)
        self.addCleanup(second_parent.close)
        def first():
            original = self.manifest_runtime.Manifest.read
            captured = []
            def read(manifest, path, **kwargs):
                result = original(manifest, path, **kwargs)
                if path == self.source and not captured:
                    captured.append(True)
                    first_child.send('snapshot captured')
                    first_child.recv()
                return result
            self.manifest_runtime.Manifest.read = read
            try:
                first_child.send(self.activation.install_trust())
            except (ValueError, self.module.ActivationError):
                first_child.send('rejected')
        def second():
            try:
                second_child.send(self.activation.install_trust())
            except (ValueError, self.module.ActivationError):
                second_child.send('rejected')
        one = context.Process(target=first)
        two = context.Process(target=second)
        def cleanup(process):
            if process.is_alive():
                process.terminate()
            process.join(5)
        one.start()
        self.addCleanup(cleanup, one)
        self.assertTrue(first_parent.poll(5))
        self.assertEqual('snapshot captured', first_parent.recv())
        with self.activation.lock_path.open('rb') as probe:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.trust_candidate({'device': self.pem_b})
        two.start()
        self.addCleanup(cleanup, two)
        first_parent.send('continue')
        self.assertTrue(first_parent.poll(5))
        self.assertTrue(second_parent.poll(5))
        outcomes = [first_parent.recv(), second_parent.recv()]
        self.assertEqual(['changed', 'rejected'], sorted(outcomes))
        self.assertEqual(self.pem_b, (self.trust_root / 'device.pem').read_text())
        self.assertEqual(1, (self.trust_root / 'device.pem').stat().st_nlink)

class TrustHardInterruptionTests(TrustFixture):
    def test_leftover_two_link_stage_recovers_to_one_immutable_final_link(self):
        stage = self.trust_root / ('.trust-stage-device-' + 'b' * 32)
        target = self.trust_root / 'device.pem'
        self.write(stage, self.pem_a)
        os.link(stage, target)
        self.assertEqual(2, target.stat().st_nlink)
        self.trust_candidate({'device': self.pem_b})
        with self.assertRaises(ValueError):
            self.activation.install_trust()
        self.assertFalse(stage.exists())
        self.assertEqual(1, target.stat().st_nlink)
        self.assertEqual(self.pem_a, target.read_text())

    def test_unrelated_second_link_is_not_removed_as_abandoned_stage(self):
        stage = self.trust_root / ('.trust-stage-device-' + 'c' * 32)
        unrelated = self.trust_root / 'other.pem'
        self.write(stage, self.pem_a)
        os.link(stage, unrelated)
        self.trust_candidate({'device': self.pem_a})
        with self.assertRaises((ValueError, OSError)):
            self.activation.install_trust()
        self.assertEqual(2, unrelated.stat().st_nlink)
        self.assertEqual(self.pem_a, unrelated.read_text())
        self.assertFalse((self.trust_root / 'device.pem').exists())


class TrustCommandTests(TrustFixture):
    def test_fixed_action_reports_change_and_rejects_path_arguments(self):
        import contextlib
        import io
        self.trust_candidate({'device': self.pem_a})
        output = io.StringIO()
        with mock.patch.object(self.module.os, 'geteuid', return_value=0), \
                mock.patch.object(self.module, 'Activator', return_value=self.activation), \
                contextlib.redirect_stdout(output):
            self.assertEqual(0, self.module.main(['install-trust']))
            self.assertEqual(0, self.module.main(['install-trust']))
        self.assertEqual('changed\nunchanged\n', output.getvalue())
        with mock.patch.object(self.module, 'Activator', side_effect=AssertionError('unexpected host access')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, self.module.main(['install-trust', '/alternate']))

    def test_pending_tls_stops_trust_installation(self):
        self.trust_candidate({'device': self.pem_a})
        self.activation.tls_journal.parent.mkdir(mode=0o700)
        self.write(self.activation.tls_journal, '{}', 0o600)
        with self.assertRaises(self.module.ActivationError):
            self.activation.install_trust()
        self.assertEqual([], list(self.trust_root.iterdir()))
