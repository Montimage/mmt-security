# Mechanism: phpAfterShell (CVE-2026-126714) — upload-progress trigger request

PHP's file-based session handler rewrites the session file while it is still
parsing an unauthenticated `multipart/form-data` request — before the target
script runs. A multipart field named `PHP_SESSION_UPLOAD_PROGRESS` (the default
`session.upload_progress.name`) makes the RFC1867 upload-progress callback open
the session resolved from the `PHPSESSID` cookie, update it and write it back.
phpAfterShell kills the PHP worker in the middle of that write, leaving a
session file that is new-prefix + old-tail; a later `session_start()` then
unserializes attacker-influenced bytes as objects, which a gadget chain turns
into remote code execution. It bypasses the October 2026 "PHP2Shell" fix.

A network detector sees only the precondition: one request that is at once
- a `POST`,
- `Content-Type: multipart/form-data`,
- a body containing the literal field name `PHP_SESSION_UPLOAD_PROGRESS`,
- a `Cookie: PHPSESSID=<sid>` header (PHP defaults to cookie-only SIDs).

mmt-security rule 230 (`rules/230.phpaftershell.xml`) fires on exactly that
conjunction. The interrupted write and the follow-up session read are not
distinguishable on the wire, so the rule alerts on the trigger, shared with the
earlier PHP2Shell attempts.

This lab sends the trigger over cleartext HTTP/1.1 on TCP 80 to a static nginx
that executes nothing — the request bytes are the evidence; a PHP server is not
needed to produce them. Real exploitation usually targets HTTPS, which a
payload detector cannot inspect (a documented limit of the rule, not of the lab).

## attack.pcap
Three POSTs on distinct TCP connections, each `multipart/form-data` with a
`PHPSESSID` cookie and the `PHP_SESSION_UPLOAD_PROGRESS` field in the body —
once as the first field, once after the file part. Every such request must make
rule 230 fire (3 alerts expected).

## benign.pcap
Two GETs and one multipart/form-data POST carrying an ordinary `file` field,
all with a `PHPSESSID` cookie — the same shapes minus the field. Rule 230 must
stay silent.

## References
- [phpAfterShell: From Interrupted Session Writes to Remote Code Execution — depthfirst](https://depthfirst.com/research/phpaftershell) — attack mechanics, the `PHP_SESSION_UPLOAD_PROGRESS` reachability
- [CVE-2026-126714 record](https://www.cve.org/CVERecord?id=CVE-2026-126714) — affected versions, CWE-367/CWE-662, CVSS 9.2
- [phpAfterShell Explained — The Hacker News](https://thehackernews.com/2026/11/phpaftershell-explained-how-hackers.html) — affected/fixed PHP versions
- [RFC 1867 — Form-based File Upload in HTML](https://www.rfc-editor.org/rfc/rfc1867) — the multipart upload mechanism PHP hooks
- [PHP session upload progress](https://www.php.net/manual/en/session.upload-progress.php) — the feature and the field name
