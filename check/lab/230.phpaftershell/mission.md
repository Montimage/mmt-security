# Mission: Produce an attack/benign pair of cleartext HTTP requests where the attack carries the phpAfterShell (CVE-2026-126714) trigger — a multipart POST with a PHP_SESSION_UPLOAD_PROGRESS field and a PHPSESSID cookie — and the benign shows ordinary HTTP use of the same shapes, for testing mmt-security rule 230
- Scope: cleartext HTTP/1.1 over TCP 80 to one web server: the phpAfterShell trigger request (multipart/form-data POST carrying PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID cookie) versus normal HTTP requests including a plain multipart upload, for an mmt-security ATTACK rule
- Consumer: mmt-rule-generator: test_rule.sh --attack/--benign for rule 230; probe_attrs.sh on http.method http.content_type http.cookie http.uri http.p_payload http.p_data_len
- Protocol: HTTP/1.1 over TCP 80, cleartext
- Traces: attack.pcap — ≥1 POST multipart/form-data request whose body holds a field named PHP_SESSION_UPLOAD_PROGRESS, sent with a PHPSESSID cookie [rule 230: POST + multipart + PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID in one request; fires]
- Traces: benign.pcap — ≥1 GET and ≥1 multipart/form-data POST with a PHPSESSID cookie but no PHP_SESSION_UPLOAD_PROGRESS field [stays silent]
- Generator: lab — http-payloads template: real nginx victim and real HTTP client give real framing; the rule keys on a field value, no PHP server needed (the request bytes are the evidence)
- Server/client: nginx:1.27-alpine victim; python:3.12-slim stdlib http.client generator
- Destination: check/lab/230.phpaftershell/; traces copied to check/pcap/230.phpaftershell.pcap and 230.phpaftershell_benign.pcap
- Out of scope: the server-side session-file corruption and the follow-up session_start() request (not distinguishable on the wire); HTTPS

## Log
- 2026-11-19: initial request from mmt-rule-generator (rule 230, phpAfterShell CVE-2026-126714) → attack.pcap, benign.pcap
