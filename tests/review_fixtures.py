"""Synthetic evidence for offline review tests; no live log data."""
import hashlib


def synthetic_groups():
    examples = []
    for number in range(24):
        examples.append(('pbx', 'php', 'warning', '/sbin/iptables -w5 -W10000 '+
                         ('-A' if number%2 else '-D')+' fpbxregistrations -s 192.0.2.'+str(number+10)+'/32 -j fpbxknownreg'))
    examples += [
        ('pbx','crontab','info','(asterisk) LIST (asterisk)'),
        ('pbx','crontab','info','(asterisk) REPLACE (asterisk)'),
        ('pbx','cron','info','(asterisk) RELOAD (crontabs/asterisk)'),
        ('pbx','runuser','info','pam_unix(runuser:session): session opened for user asterisk(uid=999) by (uid=0)'),
        ('pbx','runuser','info','pam_unix(runuser:session): session closed for user asterisk'),
        ('pbx','CRON','info','(asterisk) CMD ([ -e /usr/sbin/fwconsole ] && /usr/sbin/fwconsole job --run --quiet)'),
        ('NAS','Hyper_Backup','error','SYSTEM: [Local][Local USB Storage] Failed to run backup task.'),
        ('NAS','Hyper_Backup','error','Backup failed: backup destination does not exist.'),
        ('HA','homeassistant','error','ERROR [reolink_aio.api] Host 192.0.2.80:443: API returned HTTP status ERROR code 502/Bad Gateway.'),
        ('HA','homeassistant','error','ERROR [reolink_aio.api] Host 192.0.2.83:443: API returned HTTP status ERROR code 502/Bad Gateway.'),
        ('HA','homeassistant','error','File "/usr/local/lib/python3.14/site-packages/reolink_aio/api.py", line 6052, in send'),
        ('HA','homeassistant','error','await self.login()'),
        ('HA','homeassistant','error','await self._login_open_port()'),
        ('HA','homeassistant','error','Traceback (most recent call last):'),
        ('HA','homeassistant','error',"Error setting up automation triggers: Target selector {'entity_id': []} does not have any selectors defined"),
        ('HA','hassio_supervisor','info',"Home Assistant Core state changed to APIState(core_state='NOT_RUNNING', offline_db_migration=False)"),
        ('HA','hassio_supervisor','info',"Home Assistant Core state changed to APIState(core_state='RUNNING', offline_db_migration=False)"),
        ('hypervisor','systemd','info','Finished Daily apt download activities.'),
        ('hypervisor','systemd','info','Started Daily apt download activities.'),
        ('hypervisor','kernel','error','Out of memory: Killed process 2468 (example-service)'),
        ('hypervisor','kernel','warning','audit: type=1400 audit(1793512800.123:42): apparmor="DENIED" operation="open" profile="example" name="/etc/example.conf" pid=123 comm="example" requested_mask="r" denied_mask="r"'),
        ('network','openvpn','error','TLS Error: TLS key negotiation failed to occur within 60 seconds'),
        ('network','openvpn','info','Initialization Sequence Completed'),
        ('network','kea-dhcp4','info','DHCP4_LEASE_ALLOC [hwtype=1 02:00:00:00:00:01], cid=[no info], tid=0x1234: lease 192.0.2.100 has been allocated for 86400 seconds'),
    ]
    result=[]
    for index,(source,program,level,message) in enumerate(examples):
        result.append(dict(id='home-'+hashlib.sha256(message.encode()).hexdigest()[:16],
            source=source,host='synthetic-'+source,program=program,reported_level=level,
            reported_priority='3' if level=='error' else '4' if level=='warning' else '6',
            message=message,example_message=message,message_truncated=False,
            count=1 if index<24 else 20,first=1793502000,last=1793505600,
            priority_hint=1 if level in ('error','warning') else 3))
    return result
