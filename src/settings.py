"""Non-secret runtime settings, loaded from environment by systemd or the runner."""
import ipaddress
import os
import re
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

def local_url(value):
    url = urlsplit(value)
    if url.scheme not in ('http', 'https') or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        raise ValueError('Ollama URL must be a plain local origin without credentials or a path')
    host = url.hostname
    if host != 'localhost':
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError('Use localhost or a literal LAN IP for Ollama') from None
        allowed = address.is_loopback or any(address in block for block in (
            ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('fc00::/7')) if address.version == block.version)
        if not allowed or address.is_unspecified:
            raise ValueError('Ollama URL must use a loopback or private LAN address')
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError('Invalid Ollama port')
    return value.rstrip('/')

def local_model(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}', value) or 'cloud' in value.lower():
        raise ValueError('Use a downloaded local model, not a cloud model')
    return value

def load():
    zone = os.environ.get('AI_MONITOR_TIMEZONE', 'America/New_York')
    ZoneInfo(zone)
    return {'ollama_url': local_url(os.environ.get('AI_MONITOR_OLLAMA_URL', 'http://127.0.0.1:11434')),
            'model': local_model(os.environ.get('AI_MONITOR_MODEL', 'qwen3:8b')),
            'timezone': zone,
            'home_nas': os.environ.get('AI_MONITOR_HOME_NAS', 'home-nas.invalid'),
            'work_nas': os.environ.get('AI_MONITOR_WORK_NAS', 'work-nas.invalid')}
