#!/usr/bin/env python3
"""Conservative local credential redaction. IPs, MACs and event times stay useful.

This is pattern-based minimization, not a guarantee of anonymization. Original
evidence remains on the NAS; coordinator caches and legacy rows are separate.
"""
import json
import re

VERSION = 'credentials-v1'
MARK = '[REDACTED]'
KEY = r'(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|authorization|proxy-authorization|cookie|set-cookie|private[_-]?key)'
SENSITIVE_KEY = re.compile(r'^(?:' + KEY + r')$', re.I)
KV = re.compile(r'''(?ix)(\b''' + KEY + r'''\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\]]+)''')
HEADER = re.compile(r'(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+')
AUTH = re.compile(r'(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+')
USERINFO = re.compile(r'(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@')
PEM = re.compile(r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----.*?-----END (?:[A-Z0-9 ]*PRIVATE KEY)-----', re.S)
JWT = re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b')
ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))')
RAW_BYTES = {'sqlite_blob_hex', 'raw_hex', 'original_hex', 'original_bytes_hex', 'raw_bytes_hex'}
BIDI = frozenset((*range(0x202a, 0x202f), *range(0x2066, 0x206a)))


def text(value):
    if value is None:
        return ''
    value = str(value)
    # NAS adapter messages can contain serialized dictionaries. Redact their
    # values structurally so escaped quotes cannot bypass key/value patterns.
    if len(value) <= 1024 * 1024 and value.lstrip().startswith(('{', '[')):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (dict, list)):
                value = json.dumps(record(parsed), ensure_ascii=True, separators=(',', ':'))
        except (ValueError, RecursionError):
            pass
    value = ANSI.sub('', value)
    value = PEM.sub('[REDACTED PRIVATE KEY]', value)
    value = HEADER.sub(lambda match: match[1] + MARK, value)
    value = AUTH.sub(lambda match: match[1] + ' ' + MARK, value)
    value = USERINFO.sub(lambda match: match[1] + '[REDACTED]@', value)
    value = JWT.sub(MARK, value)
    value = KV.sub(lambda match: match[1] + '"' + MARK + '"', value)
    # Remove terminal controls and Unicode direction overrides; keep line breaks
    # until the destination chooses its own text layout.
    return ''.join(char for char in value if char in '\n\r\t' or
                   (ord(char) >= 32 and ord(char) != 127 and
                    ord(char) not in BIDI))


def record(value, depth=0):
    if depth > 24:
        return '[OMITTED: nesting limit]'
    if isinstance(value, dict):
        return {str(key): MARK if SENSITIVE_KEY.fullmatch(str(key)) else
                '[OMITTED: encoded bytes; original on NAS]' if str(key).lower() in RAW_BYTES else
                record(item, depth+1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [record(item, depth+1) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return '[OMITTED: binary value; original on NAS]'
    return text(value) if isinstance(value, str) else value
