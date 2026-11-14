"""Private DNS verification, conservative alias binding and packet boundaries."""
import copy
import hashlib
import importlib.util
import ipaddress
from pathlib import Path
import struct
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('device_dns_test', ROOT / 'src' / 'device_dns.py')
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)
NOW = 1794657600


def device(host, ip, site='home', kind='host'):
    scope = {'site': site, 'kind': kind, 'host': host, 'ip': ip}
    return {'id': hashlib.sha256(repr(scope).encode()).hexdigest(), 'scope': scope}


def record(name, kind, value, ttl=300):
    return {'name': name, 'type': kind, 'value': value, 'ttl': ttl}


def reverse(ip):
    return ipaddress.ip_address(ip).reverse_pointer


with tempfile.TemporaryDirectory() as folder:
    config = Path(folder) / 'resolv.conf'
    # Neither a public resolver nor search order may be used for short hostnames.
    config.write_text('search work.lan home.lan\nnameserver 8.8.8.8\nnameserver 192.168.1.1\n')
    facts = {}
    def add(name, kind, *values):
        facts[(name, kind)] = [record(name, kind, value) for value in values]
    add(reverse('192.168.1.20'), 'PTR', 'device.home.lan')
    add(reverse('192.168.2.20'), 'PTR', 'device.home.lan')
    add('device.home.lan', 'A', '192.168.1.20', '192.168.2.20')
    add('alias.home.lan', 'A', '192.168.1.20')
    add('old.home.lan', 'A', '192.168.1.99')
    add('second.home.lan', 'A', '192.168.2.20')
    add('cname.home.lan', 'A')
    facts[('cname.home.lan', 'A')] = [record('cname.home.lan', 'CNAME', 'device.home.lan')]
    calls = []
    def query(resolver, name, kind, timeout):
        assert resolver == '192.168.1.1' and 0 < timeout <= 0.8
        calls.append((name, kind))
        return facts.get((name, kind), [])
    canonical = device('device.home.lan', '192.168.1.20')
    alias = device('alias', '192.168.1.20')
    secondary = device('second.home.lan', '192.168.2.20')
    cname = device('cname.home.lan', '192.168.1.20')
    stale = device('old.home.lan', '192.168.1.20')
    remote = device('device.home.lan', '192.168.1.20', site='work')
    inputs = [canonical, alias, secondary, cname, stale, remote,
              device('NAS', '192.168.1.20', kind='nas-local'),
              device('public.home.lan', '8.8.8.8'), device('missing.home.lan', '')]
    original = copy.deepcopy(inputs)
    result = dns.resolve_clusters(inputs, resolver_path=config, now=NOW, query=query)
    assert inputs == original
    assert result['resolvers'] == ['192.168.1.1']
    assert set(result['bindings']) == {d['id'] for d in (canonical, alias, secondary, cname, remote)}
    keys = {result['bindings'][d['id']]['cluster_key'] for d in (canonical, alias, secondary, cname)}
    assert len(keys) == 1 and result['bindings'][remote['id']]['cluster_key'] not in keys
    assert result['conflicts'] == [stale['id']]
    assert ('alias.home.lan', 'A') in calls and ('alias.work.lan', 'A') not in calls
    assert len(calls) == len(set(calls))  # Shared evidence is cached within one pass.
    assert all(b['expires_utc'] == NOW + 300 for b in result['bindings'].values())
    # If an IP is reused, the old observed hostname must still agree with current DNS.
    add(reverse('192.168.1.99'), 'PTR', 'new.home.lan')
    add('new.home.lan', 'A', '192.168.1.99')
    reused = device('device.home.lan', '192.168.1.99')
    result = dns.resolve_clusters([reused], resolver_path=config, now=NOW, query=query)
    assert not result['bindings'] and result['conflicts'] == [reused['id']]
    # Missing or ambiguous DNS is not a positive contradiction of old evidence.
    add(reverse('192.168.1.21'), 'PTR', 'a.home.lan', 'b.home.lan')
    unknown = device('unknown.home.lan', '192.168.1.22')
    ambiguous = device('ambiguous.home.lan', '192.168.1.21')
    result = dns.resolve_clusters([unknown, ambiguous], resolver_path=config, now=NOW, query=query)
    assert not result['bindings'] and not result['conflicts']
    def unavailable(*args): raise OSError('synthetic timeout')
    result = dns.resolve_clusters([canonical], resolver_path=config, now=NOW, query=unavailable)
    assert not result['complete'] and not result['bindings'] and not result['conflicts']
    # An alias loop or unrelated answer cannot authorize a binding.
    facts[('alias.home.lan', 'A')] = [record('alias.home.lan', 'CNAME', 'loop.home.lan'),
                                     record('loop.home.lan', 'CNAME', 'alias.home.lan')]
    result = dns.resolve_clusters([canonical, alias], resolver_path=config, now=NOW, query=query)
    assert alias['id'] not in result['bindings']
    facts[('alias.home.lan', 'A')] = [record('unrelated.home.lan', 'A', '192.168.1.20')]
    result = dns.resolve_clusters([canonical, alias], resolver_path=config, now=NOW, query=query)
    assert alias['id'] not in result['bindings']
    # PTR domain must be permitted for this site; explicit domains support all-short inventories.
    add('alias.home.lan', 'A', '192.168.1.20')
    assert not dns.resolve_clusters([alias], resolver_path=config, now=NOW, query=query)['bindings']
    assert alias['id'] in dns.resolve_clusters([alias], resolver_path=config, now=NOW,
        query=query, site_domains={'home': ['home.lan']})['bindings']
    assert not dns.resolve_clusters([alias], resolver_path=config, now=NOW,
        query=query, site_domains={'home': ['work.lan']})['bindings']
    # ULA IPv6 follows the same PTR + AAAA confirmation; internet IPv6 never qualifies.
    ipv6 = device('v6.home.lan', 'fd12:3456::20')
    add(reverse('fd12:3456::20'), 'PTR', 'v6.home.lan')
    add('v6.home.lan', 'AAAA', 'fd12:3456::20')
    assert ipv6['id'] in dns.resolve_clusters([ipv6], resolver_path=config, now=NOW, query=query)['bindings']
    ipv6_literal = device('fd12:3456::20', 'fd12:3456::20')
    result = dns.resolve_clusters([ipv6, ipv6_literal], resolver_path=config, now=NOW, query=query)
    assert result['bindings'][ipv6['id']]['cluster_key'] == result['bindings'][ipv6_literal['id']]['cluster_key']
    assert dns.private_address('2001:4860:4860::8888') is None
    # Zero time budget and absence of private resolvers never trigger network calls.
    result = dns.resolve_clusters([canonical], resolver_path=config, now=NOW, seconds=0, query=query)
    assert not result['complete'] and result['queries'] == 0
    config.write_text('nameserver 8.8.8.8\nnameserver 127.0.0.53\n')
    result = dns.resolve_clusters([canonical], resolver_path=config, now=NOW, query=query)
    assert not result['complete'] and result['queries'] == 0

# Parse real DNS framing, including rejection of spoofed/truncated/compression-loop replies.
name = 'device.home.lan'
question = dns._wire_name(name) + struct.pack('!2H', 1, 1)
answer = b'\xc0\x0c' + struct.pack('!2HIH', 1, 1, 300, 4) + ipaddress.ip_address('192.168.1.20').packed
packet = struct.pack('!6H', 1234, 0x8180, 1, 1, 0, 0) + question + answer
assert dns.parse_response(packet, 1234, name, 'A') == [record(name, 'A', '192.168.1.20')]
for invalid, ident, expected in ((packet, 99, name), (packet, 1234, 'other.home.lan'),
        (packet[:-1], 1234, name), (packet + b'x', 1234, name),
        (packet[:2] + struct.pack('!H', 0x8380) + packet[4:], 1234, name)):
    try:
        dns.parse_response(invalid, ident, expected, 'A')
        raise AssertionError('Invalid DNS packet accepted')
    except ValueError:
        pass
try:
    dns._read_name(b'\xc0\x00', 0)
    raise AssertionError('DNS compression loop accepted')
except ValueError:
    pass

print('PASS: private-only local DNS, forward/reverse aliases, CNAMEs, stale IP conflicts, site separation, short-name suffixes, missing/ambiguous DNS, budgets and packet validation')
