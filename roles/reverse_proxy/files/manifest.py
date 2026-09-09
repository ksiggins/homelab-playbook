"""Private desired manifest snapshots, ingress binding, and effective selection."""
import copy
import hashlib
import json
import os
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

    def read(self, path):
        self.a.parents(path)
        expected = self.a.metadata(path, stat.S_ISREG, self.a.ids[0], self.a.ids[1], 0o600)
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
