"""HTTP lab client: send each request of a JSON-lines file, one TCP connection per request.

Usage: client.py <host> <requests.jsonl>
Each line: {"name": "...", "method": "GET", "path": "/", "headers": {"K": "V"}, "body": "..."}
Standard library only (the lab network is internal: nothing can be installed at run time).
Exits 1 when the file is missing or a line is not valid JSON, 2 when no request got a response.
"""
import http.client
import json
import sys
import time

host, path = sys.argv[1], sys.argv[2]
time.sleep(2)  # let tcpdump start
try:
    lines = [l for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("#")]
except OSError as e:
    sys.exit(f"Error: cannot read {path}: {e}. Put one JSON request per line in payloads/<mode>.jsonl.")
ok = 0
for n, line in enumerate(lines, 1):
    try:
        r = json.loads(line)
    except json.JSONDecodeError as e:
        sys.exit(f"Error: {path} line {n} is not JSON ({e}).")
    body = r.get("body")
    c = http.client.HTTPConnection(host, 80, timeout=5)
    try:
        c.request(r.get("method", "GET"), r.get("path", "/"), body=body.encode() if body else None,
                  headers={"Host": "victim", **r.get("headers", {})})
        status = c.getresponse().status
        ok += 1
        print(f"{r.get('name', n)}: {status}")
    except OSError as e:
        print(f"{r.get('name', n)}: no response ({e})")
    finally:
        c.close()
    time.sleep(0.2)
if ok == 0:
    sys.exit("Error: no request got a response; is the victim up?")
