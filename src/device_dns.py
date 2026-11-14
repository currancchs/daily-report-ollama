"""Bounded, forward-confirmed local DNS evidence for observed device aliases.

Only the collector calls this module. It never changes identities or queries an
external resolver; uncertain DNS leaves devices separate for the caller to handle.
"""
import hashlib
import ipaddress
from pathlib import Path
import re
import secrets
import socket
import struct
import time

PRIVATE = tuple(ipaddress.ip_network(value) for value in
                ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))
TYPES = {'A': 1, 'CNAME': 5, 'PTR': 12, 'AAAA': 28}
MAX_QUERIES = 160


def private_address(value):
    try:
        address = ipaddress.ip_address(value)
        return address if any(address in network for network in PRIVATE
                              if address.version == network.version) else None
    except (ValueError, TypeError):
        return None


def hostname(value):
    value = str(value or '').strip().lower().rstrip('.')
    if not value or len(value) > 253:
        return None
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?', label)
           for label in value.split('.')):
        return None
    return value


def local_resolvers(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('Local DNS resolver configuration is unavailable')
    result = []
    for line in path.read_text(encoding='ascii', errors='strict').splitlines():
        fields = re.split(r'\s+', re.split(r'[#;]', line, maxsplit=1)[0].strip())
        if len(fields) >= 2 and fields[0] == 'nameserver':
            address = private_address(fields[1])
            if address is not None and str(address) not in result:
                result.append(str(address))
    if not result:
        raise ValueError('No private local DNS resolver is configured')
    return result[:3]


def _wire_name(name):
    normalized = hostname(name)
    if normalized is None:
        raise ValueError('Invalid DNS hostname')
    return b''.join(bytes((len(label),)) + label.encode('ascii')
                    for label in normalized.split('.')) + b'\0'


def _read_name(packet, offset):
    labels, visited, end = [], set(), None
    for _ in range(128):
        if offset >= len(packet) or offset in visited:
            raise ValueError('Invalid DNS name pointer')
        visited.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('Truncated DNS pointer')
            pointer = ((length & 0x3f) << 8) | packet[offset + 1]
            if pointer >= offset:
                raise ValueError('Forward DNS pointer')
            if end is None: end = offset + 2
            offset = pointer
            continue
        if length & 0xc0 or length > 63 or offset + 1 + length > len(packet):
            raise ValueError('Invalid DNS label')
        offset += 1
        if not length:
            name = '.'.join(labels)
            if name and hostname(name) is None:
                raise ValueError('Invalid DNS answer name')
            return name, end if end is not None else offset
        labels.append(packet[offset:offset + length].decode('ascii').lower())
        if sum(len(label) + 1 for label in labels) > 254:
            raise ValueError('DNS name exceeds its bound')
        offset += length
    raise ValueError('DNS name pointer limit exceeded')


def parse_response(packet, identity, name, kind):
    if len(packet) < 12 or len(packet) > 4096:
        raise ValueError('Invalid DNS response size')
    ident, flags, questions, answers, authority, additional = struct.unpack('!6H', packet[:12])
    if (ident != identity or not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or
            questions != 1 or answers > 64 or answers + authority + additional > 128):
        raise ValueError('Unexpected DNS response header')
    question, offset = _read_name(packet, 12)
    if offset + 4 > len(packet): raise ValueError('Truncated DNS question')
    question_type, question_class = struct.unpack('!2H', packet[offset:offset + 4])
    offset += 4
    if (question != hostname(name) or question_type != TYPES[kind] or question_class != 1):
        raise ValueError('Unexpected DNS response question')
    if flags & 15 == 3: return []  # NXDOMAIN is uncertainty, never positive conflict.
    if flags & 15: raise ValueError('DNS server did not answer successfully')
    result = []
    for index in range(answers + authority + additional):
        owner, offset = _read_name(packet, offset)
        if offset + 10 > len(packet): raise ValueError('Truncated DNS record')
        record_type, record_class, ttl, length = struct.unpack('!2HIH', packet[offset:offset + 10])
        offset += 10
        stop = offset + length
        if stop > len(packet): raise ValueError('Truncated DNS record data')
        value = None
        if record_class == 1:
            if record_type == TYPES['A'] and length == 4:
                value = str(ipaddress.ip_address(packet[offset:stop]))
            elif record_type == TYPES['AAAA'] and length == 16:
                value = str(ipaddress.ip_address(packet[offset:stop]))
            elif record_type in (TYPES['PTR'], TYPES['CNAME']):
                value, name_end = _read_name(packet, offset)
                if name_end != stop: raise ValueError('Invalid DNS record length')
        if index < answers and value is not None:
            result.append({'name': owner, 'type': next(key for key, number in TYPES.items()
                           if number == record_type), 'value': value, 'ttl': ttl})
        offset = stop
    if offset != len(packet): raise ValueError('Trailing DNS response bytes')
    return result


def udp_query(resolver, name, kind, timeout):
    address = private_address(resolver)
    if address is None or kind not in TYPES or not 0 < timeout <= 2:
        raise ValueError('Invalid local DNS query')
    identity = secrets.randbits(16)
    packet = struct.pack('!6H', identity, 0x0100, 1, 0, 0, 0) + _wire_name(name) + struct.pack('!2H', TYPES[kind], 1)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as channel:
        channel.settimeout(timeout)
        # Connected UDP only accepts replies from this exact private resolver.
        channel.connect((str(address), 53))
        channel.send(packet)
        response = channel.recv(4097)
    return parse_response(response, identity, name, kind)


def resolve_clusters(devices, *, resolver_path=Path('/etc/resolv.conf'), now=None,
                     seconds=8, query=None, site_domains=None):
    """Return current verified bindings and positive conflicts, never mutations.

    A binding requires one local PTR name, forward confirmation of its private IP,
    and forward agreement for the observed hostname. Short aliases are resolved in
    the PTR name's own suffix, never in resolv.conf search order. Domain suffixes
    are inferred per site from observed FQDN scopes unless explicitly supplied.
    query injection is for offline tests: query(resolver, name, type, timeout).
    """
    now = int(time.time() if now is None else now)
    seconds = min(15, max(0, float(seconds)))
    deadline = time.monotonic() + seconds
    result = {'bindings': {}, 'conflicts': [], 'checked_utc': now, 'resolvers': [],
              'queries': 0, 'complete': True, 'errors': []}
    try:
        result['resolvers'] = local_resolvers(resolver_path)
    except (OSError, ValueError, UnicodeError):
        result.update(complete=False, errors=['Private local DNS configuration unavailable'])
        return result
    domains = {site: set() for site in ('home', 'work')}
    if site_domains is not None:
        for site in domains:
            for value in site_domains.get(site, ()):
                value = hostname(value)
                if value and '.' in value: domains[site].add(value)
    else:
        for device in devices:
            scope = device.get('scope', {})
            site, host = scope.get('site'), hostname(scope.get('host'))
            if site not in domains or scope.get('kind') == 'nas-local' or not private_address(scope.get('ip')):
                continue
            if host and '.' in host and not private_address(host):
                try: ipaddress.ip_address(host)
                except ValueError: domains[site].add(host.split('.', 1)[1])
    query = query or udp_query
    cache = {}
    selected_resolver = [None]

    def ask(name, kind):
        key = (name, kind)
        if key in cache: return cache[key]
        if time.monotonic() >= deadline or result['queries'] >= MAX_QUERIES:
            raise TimeoutError('DNS verification budget exhausted')
        responses = []
        # Once a resolver answers, use that same DNS view for every confirmation
        # in this pass. Do not combine a PTR from one resolver with another's A.
        candidates = [selected_resolver[0]] if selected_resolver[0] else result['resolvers']
        for resolver in candidates:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or result['queries'] >= MAX_QUERIES:
                raise TimeoutError('DNS verification budget exhausted')
            result['queries'] += 1
            try:
                responses = query(resolver, name, kind, min(0.8, remaining))
                selected_resolver[0] = resolver
                break
            except (OSError, ValueError, UnicodeError):
                continue
        else:
            raise OSError('Local DNS query unavailable')
        if not isinstance(responses, list) or len(responses) > 64:
            raise ValueError('Invalid local DNS answers')
        cache[key] = responses
        return responses

    def addresses(name, kind):
        current, seen, ttl = name, set(), 86400
        for _ in range(8):
            if current in seen: raise ValueError('DNS alias cycle')
            seen.add(current)
            records = ask(current, kind)
            # Every owner is checked; unrelated answer records cannot confirm IPs.
            for _ in range(8):
                relevant = [r for r in records if r.get('name') == current]
                aliases = {hostname(r.get('value')) for r in relevant if r.get('type') == 'CNAME'}
                values = {str(ipaddress.ip_address(r['value'])) for r in relevant if r.get('type') == kind}
                evidence = [r for r in relevant if r.get('type') in ('CNAME', kind)]
                if any(type(r.get('ttl')) is not int or r['ttl'] <= 0 for r in evidence):
                    raise ValueError('DNS evidence has no cache lifetime')
                if evidence: ttl = min(ttl, *(r['ttl'] for r in evidence))
                if aliases:
                    if len(aliases) != 1 or None in aliases or values:
                        raise ValueError('Ambiguous DNS alias')
                    current = next(iter(aliases))
                    if current in seen: raise ValueError('DNS alias cycle')
                    seen.add(current)
                    if any(r.get('name') == current for r in records): continue
                    seen.remove(current)
                    break
                return values, ttl
            else:
                raise ValueError('DNS alias bound exceeded')
        raise ValueError('DNS alias bound exceeded')

    for device in devices:
        scope = device.get('scope', {})
        identity, site = device.get('id'), scope.get('site')
        address = private_address(scope.get('ip'))
        observed_address = private_address(scope.get('host'))
        observed = str(observed_address) if observed_address is not None else hostname(scope.get('host'))
        if (not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity) or
                site not in domains or not domains[site] or scope.get('kind') == 'nas-local' or
                address is None or observed is None):
            continue
        if observed_address is not None and observed_address != address: continue
        ip, kind = str(address), 'AAAA' if address.version == 6 else 'A'
        try:
            records = ask(address.reverse_pointer, 'PTR')
            pointers = [r for r in records if r.get('name') == address.reverse_pointer and r.get('type') == 'PTR']
            names = {hostname(r.get('value')) for r in pointers}
            if len(names) != 1 or None in names: continue
            canonical = next(iter(names))
            if not any(canonical.endswith('.' + domain) for domain in domains[site]): continue
            if any(type(r.get('ttl')) is not int or r['ttl'] <= 0 for r in pointers): continue
            canonical_ips, canonical_ttl = addresses(canonical, kind)
            if ip not in canonical_ips:
                if canonical_ips: result['conflicts'].append(identity)
                continue
            if observed == ip:
                observed_ttl = canonical_ttl
            else:
                if '.' not in observed:
                    observed += '.' + canonical.split('.', 1)[1]
                observed_ips, observed_ttl = addresses(observed, kind)
                if ip not in observed_ips:
                    if observed_ips: result['conflicts'].append(identity)
                    continue
            ttl = min(canonical_ttl, observed_ttl, *(r['ttl'] for r in pointers), 86400)
            result['bindings'][identity] = {'cluster_key': hashlib.sha256((site + '\0' + canonical).encode()).hexdigest(),
                'canonical': canonical, 'ip': ip, 'verified_utc': now, 'expires_utc': now + ttl}
        except TimeoutError:
            result['complete'] = False
            if 'Local DNS verification reached its time or query limit' not in result['errors']:
                result['errors'].append('Local DNS verification reached its time or query limit')
            break
        except (OSError, ValueError, TypeError, UnicodeError):
            result['complete'] = False
            if 'Some local DNS lookups were unavailable or ambiguous' not in result['errors']:
                result['errors'].append('Some local DNS lookups were unavailable or ambiguous')
    result['conflicts'] = sorted(set(result['conflicts']))
    return result
