"""Private desired manifest snapshots, ingress binding, and effective selection."""
import copy
import hashlib
import errno
import json
import os
import re
import ssl
import uuid
import stat

import proxy_config


LIMIT = 1024 * 1024


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest field')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


class Manifest:
    def __init__(self, activator):
        self.a = activator
        self.path = activator.state / 'desired.json'
        self.source = activator.state / 'desired.candidate.json'
        self.ingress = activator.state / 'ingress.candidate.json'

    def read(self, path, *, gid=None, mode=0o600):
        self.a.parents(path)
        gid = self.a.ids[1] if gid is None else gid
        expected = self.a.metadata(path, stat.S_ISREG, self.a.ids[0], gid, mode)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValueError('manifest changed before snapshot')
            data = b''
            while len(data) <= LIMIT:
                chunk = os.read(fd, min(65536, LIMIT + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            after = os.fstat(fd)
            if (len(data) > LIMIT or
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('manifest changed during snapshot or exceeds bound')
            return data
        finally:
            os.close(fd)

    def validate(self, envelope):
        if (not isinstance(envelope, dict) or set(envelope) != {'version', 'manifest', 'ingress'}
                or type(envelope['version']) is not int or envelope['version'] != 1
                or not isinstance(envelope['manifest'], str)):
            raise ValueError('invalid desired envelope')
        raw = envelope['manifest'].encode('utf-8')
        config = proxy_config.validate(decode(raw))
        ingress = envelope['ingress']
        if (not isinstance(ingress, dict) or
                set(ingress) != {'version', 'manifest_sha256', 'listen_addresses', 'https_client_networks'}
                or type(ingress['version']) is not int or ingress['version'] != 1
                or ingress['manifest_sha256'] != hashlib.sha256(raw).hexdigest()
                or ingress['listen_addresses'] != config['bind_addresses']
                or ingress['https_client_networks'] != config['client_sources']):
            raise ValueError('desired revision is not bound to verified ingress')
        return config

    def candidate(self):
        envelope = {'version': 1, 'manifest': self.read(self.source).decode('utf-8'),
                    'ingress': decode(self.read(self.ingress))}
        return envelope, self.validate(envelope)

    def committed(self):
        envelope = decode(self.read(self.path))
        return envelope, self.validate(envelope)

    def unchanged(self, expected):
        actual, unused = self.candidate()
        if actual != expected:
            raise ValueError('desired candidate changed during activation')

    def effective(self, config, generation=None):
        result = copy.deepcopy(config)
        pointer = self.a.config_dir / 'tls/infra/current'
        if generation is None and not os.path.lexists(pointer) and 'infra' in config.get('deferred_certificates', []):
            result['routes'] = [route for route in result['routes'] if route['certificate_name'] != 'infra']
        return result

    def render(self, config, generation=None):
        paths = None if generation is None else {'infra': str(generation)}
        return proxy_config.render(self.effective(config, generation), certificate_paths=paths)

    @staticmethod
    def endpoints(config):
        return {(route['hostname'], address, 443) for route in config['routes']
                if route['certificate_name'] == 'infra' for address in config['bind_addresses']}


class Trust:
    """Create immutable named bundles; the caller holds the Caddy lock."""
    _stage = re.compile(r'\.trust-stage-([A-Za-z0-9][A-Za-z0-9_-]{0,63})-[0-9a-f]{32}\Z')
    _pem = re.compile(r'(?:-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----[ \t\r\n]*)+\Z')

    def __init__(self, activator):
        self.a = activator
        self.manifests = Manifest(activator)
        self.root = activator.config_dir / 'trust'
        self.source = activator.state / 'trust.candidate.json'

    @staticmethod
    def no_acl(path):
        listxattr = getattr(os, 'listxattr', None)
        if listxattr is None:
            return
        try:
            attributes = listxattr(path, follow_symlinks=False)
        except OSError as error:
            if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
                return
            raise
        if set(attributes) & {'system.posix_acl_access', 'system.posix_acl_default'}:
            raise ValueError('trust paths must not have extended or default ACLs')

    def verify(self, target, expected):
        self.no_acl(target)
        actual = self.manifests.read(target, gid=self.a.ids[3], mode=0o640)
        if actual != expected:
            raise ValueError('trust name already identifies a different immutable bundle')

    def remove_stage(self, stage):
        match = self._stage.fullmatch(stage.name)
        if stage.parent != self.root or match is None:
            raise ValueError('trust preparation artifact name is invalid')
        info = stage.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.a.ids[0]
                or info.st_gid not in (self.a.ids[1], self.a.ids[3])
                or stat.S_IMODE(info.st_mode) not in (0o600, 0o640)
                or info.st_nlink not in (1, 2)):
            raise ValueError('trust preparation artifact metadata is invalid')
        self.no_acl(stage)
        if info.st_nlink == 2:
            target = self.root / (match.group(1) + '.pem')
            final = target.lstat()
            if (not stat.S_ISREG(final.st_mode)
                    or (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino)
                    or info.st_gid != self.a.ids[3] or stat.S_IMODE(info.st_mode) != 0o640):
                raise ValueError('trust preparation link has unexpected authority')
        stage.unlink()
        self.a.fsync_directory(self.root)

    def unchanged(self, raw):
        if self.manifests.read(self.source) != raw:
            raise ValueError('trust candidate changed during installation')

    def install(self):
        self.a.parents(self.root)
        self.a.metadata(self.root, stat.S_ISDIR, self.a.ids[0], self.a.ids[3], 0o750)
        self.no_acl(self.root)
        self.no_acl(self.source)
        raw = self.manifests.read(self.source)
        values = decode(raw)
        if not isinstance(values, dict) or len(values) > 64:
            raise ValueError('trust candidate must be a bounded name-to-PEM mapping')
        bundles = {}
        for name, pem in values.items():
            proxy_config._component(name, 'proxy trust name')
            if (not isinstance(pem, str) or not 1 <= len(pem) <= 262144
                    or self._pem.fullmatch(pem) is None):
                raise ValueError('trust bundle must contain only bounded PEM certificates')
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cadata=pem)
            except (ValueError, ssl.SSLError):
                raise ValueError('trust bundle contains invalid certificates') from None
            bundles[name] = pem.encode('ascii')
        for stage in self.root.iterdir():
            if stage.name.startswith('.trust-stage-'):
                self.remove_stage(stage)
        for name, contents in bundles.items():
            target = self.root / (name + '.pem')
            if os.path.lexists(target):
                self.verify(target, contents)
        changed = False
        for name, contents in bundles.items():
            target = self.root / (name + '.pem')
            self.unchanged(raw)
            if os.path.lexists(target):
                self.verify(target, contents)
                continue
            stage = self.root / ('.trust-stage-' + name + '-' + uuid.uuid4().hex)
            descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, 'wb') as output:
                    os.fchown(output.fileno(), self.a.ids[0], self.a.ids[3])
                    os.fchmod(output.fileno(), 0o640)
                    output.write(contents)
                    output.flush()
                    os.fsync(output.fileno())
                self.unchanged(raw)
                try:
                    # link(2) publishes complete bytes only when target is absent;
                    # unlike rename/replace it cannot overwrite a competing name.
                    os.link(stage, target, follow_symlinks=False)
                    changed = True
                    self.a.fsync_directory(self.root)
                except FileExistsError:
                    self.verify(target, contents)
            finally:
                if os.path.lexists(stage):
                    self.remove_stage(stage)
            restorecon = self.a.path('/usr/sbin/restorecon')
            if restorecon.exists():
                self.a.commands.run([str(restorecon), '-F', str(target)])
            self.verify(target, contents)
        self.unchanged(raw)
        return 'changed' if changed else 'unchanged'
