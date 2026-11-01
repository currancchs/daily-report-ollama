# Data boundaries

Local inference is the default design. Use a downloaded model, set `OLLAMA_NO_CLOUD=1` on the Ollama server, and keep its API reachable only by trusted LAN/VPN peers. The client rejects public Ollama origins, URL credentials, redirects, environment proxies, and cloud-tagged model names. This does not verify the internals of arbitrary local model aliases or network gateways; the server's cloud-disable setting still matters.

Credential-pattern redaction is a best-effort filter, not anonymization. IP addresses, device names, user names, file paths, and unexpected secrets can remain in evidence. The NAS originals and downloaded export caches are not redacted. Restrict them as operational data.

Gmail delivery sends the digest through Google over certificate-verified TLS. Do not claim the entire pipeline is offline when this option is enabled. The viewer can be used without Gmail. Ordinary model downloads and software installation also need Internet access.

Never commit `gmail.json`, `.smb` credentials, `power.key`, DPAPI pairing blobs, databases, export ZIPs, collection logs, or real report history. `.gitignore` reduces accidental staging but does not remove files already tracked. Check `git status` and `git diff --cached` before publishing.

The example HTML/JSON uses synthetic events and documentation addresses. Python test secrets are deliberately fake fixtures. The source license does not grant rights to third-party software, models, or the portfolio photographs.

Model output does not execute commands or repair systems. Missing evidence is not proof of healthy devices. The optional power guard is separate and remains disabled until explicitly enabled after a Wake-on-LAN and signed-status check.

Report potential vulnerabilities without attaching real log evidence or credentials to a public issue. Replace sensitive details with a minimal synthetic reproduction.
