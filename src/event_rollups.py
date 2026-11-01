"""Narrow grouping rules for AMI, Kea, Configurator and NAS logout logs.

Only named volatile fields vary. Unknown formats remain unchanged; grouped denials still require review.
This module performs no I/O and does not discard records or classify them benign.
"""
from datetime import datetime
import ipaddress
import json
import re

VERSION = 'event-rollups-v3-review'

NOTES = {
    'ami_denied_session': 'Repeated AMI RequestNotAllowed errors grouped by account, request type, service, addresses and transport. Only PID, timestamps, session ID and remote source port vary. These denials remain errors for review; grouping does not resolve or suppress them.',
    'nas_ftp_logout_bytes': 'Repeated NAS FTP logout records grouped by user, client and protocol. Only uploaded/downloaded byte totals vary; counts, time range and sampled totals are retained. This is not a transfer-volume audit; raw records remain in history.',
    'ami_success_session': 'Repeated AMI SuccessfulAuth events grouped by account, service, addresses, transport and password-use flag. PID, timestamps, session ID and remote source port vary. Counts and time range are retained; successful authentication does not establish authorized use.',
    'kea_dhcp4_info': 'Repeated Kea DHCPv4 INFO events grouped by client MAC/client ID, event type and lease address. Process/thread/transaction IDs vary; LEASE_REUSE remaining seconds may vary. Counts and time range are retained. INIT_REBOOT is a DHCP state, not proof of a device reboot.',
    'configurator_local_http200': 'Repeated File Editor localhost GET / HTTP 200 access entries; only the embedded log timestamp varies. Count, time range and original examples are retained. These responses do not establish overall Home Assistant health.',
}
AMI_PREFIX = re.compile(r'^SECURITY\[(?P<pid>\d+)\]: res_security_log\.c:\d+ in security_event_stasis_cb: ')
PAIR = re.compile(r'([A-Za-z][A-Za-z0-9]*)="([^"\r\n\\]*)"')
AMI_KEYS = {'SecurityEvent','EventTV','Severity','Service','EventVersion','AccountID',
            'SessionID','LocalAddress','RemoteAddress','UsingPassword','SessionTV'}
ADDRESS = re.compile(r'^(IPV[46])/(TCP|TLS|UDP)/([^/]+)/(\d{1,5})$')
KEA_HEADER = re.compile(r'^(?P<host>[A-Za-z0-9_.:-]+) kea-dhcp4 (?P<pid>\d+) - - INFO\s+'
                        r'\[(?P<logger>kea-dhcp4\.[A-Za-z0-9_.-]+)\.(?P<thread>0x[0-9a-fA-F]+)\] ')
KEA_SHORT_HEADER = re.compile(r'^INFO[ \t]+\[(?P<logger>kea-dhcp4\.[A-Za-z0-9_.-]+)\.'
                              r'(?P<thread>0x[0-9a-fA-F]+)\] ')
CONFIGURATOR_GET = re.compile(
    r'^INFO:(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}):'
    r'hass_configurator\.configurator:127\.0\.0\.1 - "GET / HTTP/1\.1" 200 -$')
KEA_BODY = re.compile(r'^(?P<event>DHCP4_LEASE_ALLOC|DHCP4_LEASE_REUSE|DHCP4_INIT_REBOOT|DHCP4_LEASE_OFFER) '
    r'\[hwtype=(?P<hwtype>\d+) (?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\], '
    r'cid=\[(?P<cid>no info|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})*)\], '
    r'tid=(?P<tid>0x[0-9a-fA-F]+): (?P<detail>.*)$')
DETAILS = {
    'DHCP4_LEASE_ALLOC': re.compile(r'lease (?P<ip>[0-9.]+) has been allocated for (?P<seconds>\d+) seconds'),
    'DHCP4_LEASE_REUSE': re.compile(r'lease (?P<ip>[0-9.]+) has been reused for (?P<seconds>\d+) seconds'),
    'DHCP4_INIT_REBOOT': re.compile(r'client is in INIT-REBOOT state and requests address (?P<ip>[0-9.]+)'),
    'DHCP4_LEASE_OFFER': re.compile(r'lease (?P<ip>[0-9.]+) will be offered'),
}

def timestamp(value):
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except (ValueError, TypeError):
        return False

def address(value):
    found = ADDRESS.fullmatch(value)
    if not found or not 0 <= int(found[4]) <= 65535:
        return None
    try:
        parsed = ipaddress.ip_address(found[3])
    except ValueError:
        return None
    return found if str(parsed.version) == found[1][-1] else None

def ami(raw, message):
    if raw.get('prog') != 'asterisk':
        return None
    prefix = AMI_PREFIX.match(message)
    if not prefix:
        return None
    text = message[prefix.end():]
    pairs = list(PAIR.finditer(text))
    # Reconstruct the entire body: reject trailing text, missing separators,
    # duplicate keys, escaped strings and unknown security schema extensions.
    if ','.join(p[0] for p in pairs) != text:
        return None
    fields = {p[1]: p[2] for p in pairs}
    denied = fields.get('SecurityEvent') == 'RequestNotAllowed'
    expected = (AMI_KEYS - {'UsingPassword'}) | {'RequestType'} if denied else AMI_KEYS
    if len(fields) != len(pairs) or set(fields) not in (expected, expected | {'Module'}):
        return None
    if (fields['SecurityEvent'] != ('RequestNotAllowed' if denied else 'SuccessfulAuth') or fields['Service'] != 'AMI' or
        fields['Severity'] != ('Error' if denied else 'Informational') or fields['EventVersion'] != '1' or
        (not fields['RequestType'] if denied else fields['UsingPassword'] not in ('0','1')) or not fields['AccountID'] or
        not re.fullmatch(r'0x[0-9a-fA-F]+', fields['SessionID']) or
        not timestamp(fields['EventTV']) or not timestamp(fields['SessionTV'])):
        return None
    remote, local = address(fields['RemoteAddress']), address(fields['LocalAddress'])
    if not remote or not local:
        return None
    varied = {'pid':prefix['pid'], 'event_time':fields['EventTV'], 'session_time':fields['SessionTV'],
              'session_id':fields['SessionID'], 'remote_source_port':remote[4]}
    replacements = {'EventTV':'<varies>','SessionTV':'<varies>','SessionID':'<varies>',
                    'RemoteAddress':'/'.join(remote.group(1,2,3)) + '/<varies>'}
    normalized = 'SECURITY[<varies>]' + message[prefix.end('pid')+1:prefix.end()]
    normalized += ','.join(k+'="'+replacements.get(k,v)+'"' for k,v in (p.group(1,2) for p in pairs))
    return normalized, 'ami_denied_session' if denied else 'ami_success_session', varied

def kea(raw, message):
    # DSM's observed RFC5424 ingestion stores VERSION=1 as prog. Match the full
    # embedded hostname/application/header; never treat arbitrary prog=1 as Kea.
    if str(raw.get('prog')) not in ('1','kea-dhcp4'):
        return None
    header = KEA_HEADER.match(message)
    short_header = False
    # Some parsed syslog has the application in prog and no embedded hostname.
    # Require that application and INFO severity before accepting the short form.
    if (header is None and raw.get('prog') == 'kea-dhcp4' and
            str(raw.get('llevel', '')).lower() == 'info'):
        header = KEA_SHORT_HEADER.match(message)
        short_header = header is not None
    if not header:
        return None
    body = KEA_BODY.fullmatch(message[header.end():])
    if not body:
        return None
    detail = DETAILS[body['event']].fullmatch(body['detail'])
    if not detail:
        return None
    try:
        ipaddress.IPv4Address(detail['ip'])
    except ValueError:
        return None
    varied = {'thread_id':header['thread'],'transaction_id':body['tid']}
    if not short_header:
        varied['pid'] = header['pid']
    tail = body['detail']
    if body['event'] == 'DHCP4_LEASE_REUSE':
        varied['remaining_lease_seconds'] = detail['seconds']
        tail = tail[:detail.start('seconds')] + '<varies>' + tail[detail.end('seconds'):]
    prefix = 'INFO [' if short_header else header['host']+' kea-dhcp4 <varies> - - INFO ['
    normalized = (prefix+header['logger']+'.<varies>] '+
        body['event']+' [hwtype='+body['hwtype']+' '+body['mac']+'], cid=['+body['cid']+'], tid=<varies>: '+tail)
    return normalized, 'kea_dhcp4_info', varied


def configurator(raw, message):
    if (raw.get('prog') != 'app_core_configurator' or
            str(raw.get('llevel', '')).lower() != 'info'):
        return None
    found = CONFIGURATOR_GET.fullmatch(message)
    if not found:
        return None
    try:
        datetime.strptime(found['timestamp'], '%Y-%m-%d %H:%M:%S,%f')
    except ValueError:
        return None
    normalized = message[:found.start('timestamp')] + '<varies>' + message[found.end('timestamp'):]
    return normalized, 'configurator_local_http200', {'log_timestamp': found['timestamp']}


FTP_LOGOUT = re.compile(r'^User \[[^\]\r\n]+\] from \[[^\]\r\n]+\] logged out the server via \[FTP\] '
    r'with totally \[(?P<uploaded>\s*\d+(?:\.\d+)? (?:bytes|KB|MB|GB|TB))\] uploaded and '
    r'\[(?P<downloaded>\s*\d+(?:\.\d+)? (?:bytes|KB|MB|GB|TB))\] downloaded\.$')


def ftp_logout(raw, message):
    if raw.get('prog') != 'Connection' or str(raw.get('llevel', '')).lower() != 'info':
        return None
    wrapper = None
    text = message
    if message.startswith('{'):
        try:
            wrapper = json.loads(message)
        except ValueError:
            return None
        if (not isinstance(wrapper, dict) or set(wrapper) != {'luser', 'msg', 'synology_table'} or
                wrapper['synology_table'] != 'connection_log' or not isinstance(wrapper['msg'], str)):
            return None
        text = wrapper['msg']
    found = FTP_LOGOUT.fullmatch(text)
    if not found:
        return None
    normalized = text
    for field in ('downloaded', 'uploaded'):
        normalized = normalized[:found.start(field)] + '<varies>' + normalized[found.end(field):]
    if wrapper is not None:
        wrapper['msg'] = normalized
        normalized = json.dumps(wrapper, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return normalized, 'nas_ftp_logout_bytes', {k:found[k].strip() for k in ('uploaded','downloaded')}


def rollup(raw, message):
    if not isinstance(message, str):
        return message, '', {}
    return ami(raw, message) or kea(raw, message) or configurator(raw, message) or ftp_logout(raw, message) or (message, '', {})
