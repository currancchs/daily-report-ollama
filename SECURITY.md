# Data boundaries

Local inference is the default design. Use a downloaded model, set `OLLAMA_NO_CLOUD=1` on the Ollama server, and keep its API reachable only by trusted LAN/VPN peers. The client rejects public Ollama origins, URL credentials, redirects, environment proxies, and cloud-tagged model names. This does not verify the internals of arbitrary local model aliases or network gateways; the server's cloud-disable setting still matters.

Credential-pattern redaction is a best-effort filter, not anonymization. IP addresses, device names, user names, file paths, and unexpected secrets can remain in evidence. The NAS originals and downloaded export caches are not redacted. Restrict them as operational data.

Gmail delivery sends the digest through Google over certificate-verified TLS. Do not claim the entire pipeline is offline when this option is enabled. The viewer can be used without Gmail. Ordinary model downloads and software installation also need Internet access.

Never commit `gmail.json`, `.smb` credentials, `power.key`, DPAPI pairing blobs, databases, export ZIPs, collection logs, or real report history. PowerGuard's live `config.json`, `recurring-policy.json`, `unattended-ticket.json`, `boot-state.json`, `last-result.json`, `decisions-*.jsonl`, stop/lock files, and installation backups are also private operational data. `.gitignore` reduces accidental staging but does not remove files already tracked. Check `git status` and `git diff --cached` before publishing.

The example HTML/JSON uses synthetic events and documentation addresses. Python test secrets are deliberately fake fixtures. The source license does not grant rights to third-party software, models, or the portfolio photographs.

Model output does not execute commands or repair systems. Missing evidence is not proof of healthy devices. The optional power guard is separate and defaults to disabled/audit-only operation. Activating shutdown and authorizing its recurring signed-in-session exception are explicit local administrative operations; see [POWER.md](docs/POWER.md).

## Optional Windows power controls

The coordinator authenticates report completion with a nonce-bound HMAC. Its HTTP endpoint is read-only and does not send a shutdown command. This authenticates the response, not the transport or the physical cause of a boot; restrict it to the intended Windows client on a trusted LAN/VPN. Keep the coordinator key and the Windows DPAPI blob out of Git, chat, and public issues. Updating PowerGuard does not require a new pairing.

The Windows pairing blob uses DPAPI `LocalMachine` scope so the SYSTEM task can read it. That scope does not isolate it from other local accounts that can read the ciphertext. Protect the installation directory and key with SYSTEM/Administrators-only access; ordinary users must not be able to read the key or modify the script, configuration, policy, state, or task. Local policy/state HMACs use a separate record prefix, but file permissions remain necessary to prevent forged records or replay of old signed state.

Recurring authorization is optional and applies only to future boots in the fixed 03:20–03:45 Eastern window, with the same Eastern date at the decision. It permits only the explicitly selected, locked console account after valid idle and early-boot observation checks. It does not prove Wake-on-LAN: a manual boot in the same window may qualify. Every RDP session, including disconnected sessions, blocks the signed-in exception. Locking or disconnecting is not evidence that work is saved, and input inactivity cannot establish that background jobs are finished. Polling also leaves a short check-to-use race.

The guard requests shutdown only after its other gates pass during 04:00–06:00 Eastern, using `/s /t 0` without `/f`. It does not kill applications, sign users out, or retry with force. A positive `shutdown.exe` timeout implicitly enables forced termination, so the grace period runs inside the guard instead. A shutdown request or zero command exit code does not prove power-off; applications may prevent completion. Use the documented stop procedure before the OS request, since `/t 0` has no abort countdown.

Timestamped decisions contain local account/session evidence and operational timing. Treat those logs and backups as private. Offline tests use synthetic credentials and replace shutdown/network/system probes; passing them does not establish an unattended target PC's real session values or prove that its applications can safely close.

Report potential vulnerabilities without attaching real log evidence or credentials to a public issue. Replace sensitive details with a minimal synthetic reproduction.

Optional suppression controls add state-changing web forms. Anyone admitted by the viewer's network rules can manage filters; there is no separate user authentication. Keep the default loopback listener, or explicitly allow only trusted LAN/VPN clients. Do not port-forward this service to the Internet. Host/origin validation, CSRF tokens, SameSite cookies and escaped output protect form handling; they do not replace network access controls.

The application is mounted at `/controls/` behind NGINX, with Gunicorn bound to loopback. It reads verified saved reports and writes only the suppression store under its systemd filesystem policy. It cannot run AI, send mail or modify imported history through a web action. Suppressed records remain in local history and may contain sensitive context. Never publish `filters.sqlite`, its WAL files, the filter audit, or `session.key`. Completed reports are immutable snapshots; changing filters does not retract a previously sent email.
