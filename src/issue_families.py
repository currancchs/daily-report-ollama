"""Presentation-only issue families; evidence, review and suppression stay intact.

Known repeated symptoms share a card, never an Ignore rule. Unknown messages,
security failures and operational logging failures retain individual visibility.
"""
import hashlib
import re


HA_OFFLINE = {
    'key': 'homeassistant_offline',
    'title': 'Offline or possibly removed devices',
    'description': ('Home Assistant could not reach devices or refresh integration data. '
        'Devices may be powered off, removed or unreachable; an integration or remote '
        'service problem is also possible. This does not confirm removal. Each affected '
        'entity, original error, severity and evidence link remains available below.'),
}
SECURITY = re.compile(
    r'wrong code|invalid (?:code|password|credential|token)|authentication|authorization|'
    r'login|log.in|unauthori[sz]ed|forbidden|access denied|permission denied|'
    r'certificate|sslerror|tls|brute.?force|securityevent|alarm_control_panel|'
    r'\b(?:401|403)\b', re.I)
LOG_PIPELINE = re.compile(r'\bsyslog\b|\brsyslog\b|\blogspout\b|log forward|log export', re.I)
CONNECTIVITY = re.compile(
    r'(?:(?:failed|unable) to|(?:cannot|could not|can.t)(?: to)?) (?:connect|reconnect|communicate|reach)|'
    r'failed to refresh communications? settings|'
    r'connection(?:\s+\w+){0,2}\s+(?:error|failed|failure|lost|closed|reset|refused|timeout|timed out)|'
    r'(?:connection|connect|clientconnector|timeout)error|'
    r'(?:error|failure) (?:connecting|communicating|fetching)|'
    r'(?:device|entity|entities).{0,160}(?:unavailable|unreachable|offline|not available)|'
    r'referenced entities.{0,160}(?:missing|not currently available)|'
    r'no route to host|network is unreachable|host is unreachable|'
    r'(?:timed out|timeout).{0,100}(?:connect|device|host)|'
    r'(?:connect|device|host).{0,100}(?:timed out|timeout)', re.I)


def _message(group):
    return str(group.get('message') or group.get('example_message') or '')


def _is_homeassistant(group):
    names = (group.get('source'), group.get('host'))
    return any(re.fullmatch(r'(?:home[-_]?assistant|hass)(?:\.[a-z0-9_.-]+)?',
                           str(value or '').strip(), re.I) for value in names)


def _media_family(group, message):
    """Approved narrow families for repetitive Plex and Jellyfin findings."""
    source = str(group.get('source') or group.get('host') or '').lower()
    lower = message.lower()
    if re.fullmatch(r'plex(?:server)?(?:\.[a-z0-9_.-]+)?', source):
        if ('tv.plex.agents.music' in lower or 'tv.plex.metadata.agents' in lower) and any(
                token in lower for token in ('failed to return a result', 'returned incomplete results',
                    'invalid metadata type', 'error parsing xml', 'error parsing content')):
            return dict(key='plex_music_metadata', title='Plex music metadata failures',
                description='Related music metadata lookup and parsing failures. Item IDs, error types and original events remain separate in the details.')
        if '[ultrablurprocessor]' in lower and any(token in lower for token in (
                'failed to get color palette', 'failed to decode image data', 'failed to select colors')):
            return dict(key='plex_artwork', title='Plex artwork processing failures',
                description='Repeated artwork decoding and color-selection failures. The individual errors and evidence are retained.')
        if 'nat: pmp, timed out waiting for response.' in lower:
            return dict(key='plex_nat_timeout', title='Plex NAT-PMP response timeouts',
                description='Repeated NAT-PMP timeout messages. These may affect automatic port mapping; they do not establish whether remote access works.')
        if 'missing x-plex-container-size header. this will fail with status code 400 in the future.' in lower:
            return dict(key='plex_request_header', title='Plex client requests missing a size header',
                description='Repeated requests lack the same required header. Individual request IDs and records remain available.')
    if re.fullmatch(r'jellyfin(?:\.[a-z0-9_.-]+)?', source):
        if 'error in "probe provider"' in lower and 'ffprobe failed - streams and format are both null' in lower:
            return dict(key='jellyfin_media_probe', title='Jellyfin media probe failures',
                description='FFprobe returned no streams or format for these files. Every affected path and original error remains available.')
        if ('error in "screen grabber"' in lower or 'i-frame image extraction failed' in lower) and 'ffmpeg image extraction failed' in lower:
            return dict(key='jellyfin_images', title='Jellyfin image extraction failures',
                description='Related FFmpeg image and screen-grab failures across media files. Fallback attempts are not evidence that processing succeeded.')
        if 'error in "the open movie database"' in lower and 'jsonexception' in lower:
            return dict(key='jellyfin_omdb_json', title='Jellyfin movie metadata response errors',
                description='The metadata provider returned JSON that could not be parsed. Affected paths and parsing details remain in the individual events.')
    return None


def classify(site, group, assessment=None, include_media=True):
    """Return a stable family descriptor, or None for an individual finding.

    Classify original log text, never an AI-written summary. Site is validated;
    callers must include it in their family key to avoid mixing Home and Work.
    Critical findings stay individually visible, including source critical levels.
    """
    if site not in ('home', 'work') or not isinstance(group, dict):
        return None
    assessment = assessment or {}
    critical = {'critical', 'crit', 'alert', 'emerg', 'emergency', 'fatal'}
    if (str(assessment.get('severity', '')).lower() in critical or any(
            str(group.get(field, '')).lower() in critical
            for field in ('severity', 'level', 'llevel', 'prio', 'reported_level', 'reported_priority')) or any(
            str(group.get(field, '')) in ('0', '1', '2') for field in ('prio', 'reported_priority'))):
        return None
    message = _message(group)
    if not message or SECURITY.search(message):
        return None
    if _is_homeassistant(group) and not LOG_PIPELINE.search(message) and CONNECTIVITY.search(message):
        return dict(HA_OFFLINE)
    return _media_family(group, message) if include_media else None


def _number(value):
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError, OverflowError):
        return 0


def group_rows(rows, include_media=True):
    """Group existing report-web rows without changing any member or dropping data.

    Every output card has members (the original rows), highest severity, record
    total, original-group count and time bounds. Ungrouped cards have family=None.
    """
    result = {}
    rank = {'critical': 0, 'warning': 1, 'info': 2}
    for index, row in enumerate(rows):
        group, assessment = row['group'], row.get('assessment') or {}
        family = classify(row['site'], group, assessment, include_media)
        key = (row['site'], 'family', family['key']) if family else (row['site'], 'individual', group['id'], index)
        if key not in result:
            result[key] = {'id': 'family-' + hashlib.sha256(repr(key).encode()).hexdigest()[:24],
                'site': row['site'], 'family': family, 'members': [], 'severity': 'info',
                'count': 0, 'group_count': 0, 'first': None, 'last': None}
        card = result[key]
        card['members'].append(row)
        card['count'] += _number(group.get('count'))
        card['group_count'] += 1
        severity = assessment.get('severity', 'info')
        if rank.get(severity, 3) < rank.get(card['severity'], 3): card['severity'] = severity
        for field, choose in (('first', min), ('last', max)):
            value = group.get(field)
            if isinstance(value, (int, float)):
                card[field] = value if card[field] is None else choose(card[field], value)
    return sorted(result.values(), key=lambda card: (rank.get(card['severity'], 3), -card['count'], card['site'], card['id']))
