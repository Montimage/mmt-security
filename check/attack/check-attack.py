#!/usr/bin/env python3
"""Check rules/mitre-attack.csv against rules/*.xml and the pinned ATT&CK list.

Run by `make check-attack` (and so by `make check`). Offline: it reads only
files of this repository. It fails (exit 1) and lists every problem when:
  - a rules/*.xml has no row, or more than one;
  - a row points to a missing rule file, or its rule_id is not the file's property_id;
  - a technique ID is not in the pinned ATT&CK Enterprise version, its name does not
    match, or its tactic is not one of the technique's tactics;
  - a 'none' row has a technique name or a tactic;
  - a confidence is not high, medium or low, or a rationale is empty;
  - a row has missing or extra fields (e.g. an unquoted comma);
  - a CVE ID is not of the form CVE-YYYY-NNNN (4 digits or more), is repeated, is on a
    'none' row, or is not cited by the row's cve_source; a cve_source is not a cve.org or
    NVD URL, or is given without CVE IDs.
"""

import argparse
import collections
import csv
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
COLUMNS = ["rule_id", "rule_file", "technique_id", "technique_name", "tactic",
           "confidence", "cve_ids", "cve_source", "rationale"]
CONFIDENCE = ("high", "medium", "low")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVE_SOURCES = ("https://www.cve.org/", "https://nvd.nist.gov/")
PROPERTY_ID_RE = re.compile(r"<property\b[^>]*?\bproperty_id\s*=\s*\"(\d+)\"", re.S)


def read_techniques(path):
    """Return ({id: (name, [tactics])}, version) from the generated list."""
    version = None
    lines = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                m = re.match(r"# MITRE ATT&CK Enterprise (\S+)", line)
                if m:
                    version = m.group(1)
            else:
                lines.append(line)
    techniques = {}
    for r in csv.DictReader(lines):
        techniques[r["technique_id"]] = (r["technique_name"], [t for t in r["tactics"].split(";") if t])
    return techniques, version


def property_id(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        text = re.sub(r"<!--.*?-->", "", f.read(), flags=re.S)
    m = PROPERTY_ID_RE.search(text)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="Check rules/mitre-attack.csv")
    ap.add_argument("--mapping", default=os.path.join(ROOT, "rules", "mitre-attack.csv"))
    ap.add_argument("--rules", default=os.path.join(ROOT, "rules"))
    ap.add_argument("--techniques", default=os.path.join(HERE, "enterprise-attack-techniques.csv"))
    args = ap.parse_args()

    errors = []
    techniques, version = read_techniques(args.techniques)
    if not version or not techniques:
        sys.exit("check-attack: cannot read the pinned ATT&CK list %s" % args.techniques)

    with open(args.mapping, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != COLUMNS:
            sys.exit("check-attack: %s: header must be %s, not %s"
                     % (args.mapping, ",".join(COLUMNS), ",".join(reader.fieldnames or [])))
        rows = []
        for r in reader:
            if None in r or None in r.values():
                errors.append("mitre-attack.csv:%d: %d fields, expected %d (quote a field that contains a comma)"
                              % (reader.line_num, len(COLUMNS) + len(r.get(None, [])) - list(r.values()).count(None),
                                 len(COLUMNS)))
            else:
                rows.append(r)

    rule_files = {os.path.basename(p) for p in glob.glob(os.path.join(args.rules, "*.xml"))}
    seen = collections.Counter(r["rule_file"] for r in rows)
    for name in sorted(rule_files):
        if seen[name] == 0:
            errors.append("%s: no row in mitre-attack.csv" % name)
        elif seen[name] > 1:
            errors.append("%s: %d rows in mitre-attack.csv, expected 1" % (name, seen[name]))

    per_technique = collections.Counter()
    per_tactic = collections.Counter()
    per_confidence = collections.Counter()
    with_cve = 0
    for line, r in enumerate(rows, start=2):
        where = "mitre-attack.csv:%d (%s)" % (line, r["rule_file"] or "?")
        if r["rule_file"] not in rule_files:
            errors.append("%s: rule file rules/%s does not exist" % (where, r["rule_file"]))
        else:
            pid = property_id(os.path.join(args.rules, r["rule_file"]))
            if pid != r["rule_id"]:
                errors.append("%s: rule_id %s, but the rule's property_id is %s" % (where, r["rule_id"], pid))

        tid, name, tactic = r["technique_id"], r["technique_name"], r["tactic"]
        if tid == "none":
            if name or tactic:
                errors.append("%s: technique 'none' must have an empty technique_name and tactic" % where)
            per_technique["none"] += 1
        elif tid not in techniques:
            errors.append("%s: %s is not a technique of ATT&CK Enterprise %s" % (where, tid, version))
        else:
            valid_name, valid_tactics = techniques[tid]
            if name != valid_name:
                errors.append("%s: %s is named '%s' in ATT&CK %s, not '%s'" % (where, tid, valid_name, version, name))
            if not tactic or tactic not in valid_tactics:
                errors.append("%s: tactic '%s' is not a tactic of %s (%s)" % (where, tactic, tid, "; ".join(valid_tactics)))
            per_technique[tid] += 1
            per_tactic[tactic] += 1

        if r["confidence"] not in CONFIDENCE:
            errors.append("%s: confidence '%s' is not one of %s" % (where, r["confidence"], ", ".join(CONFIDENCE)))
        per_confidence[r["confidence"]] += 1
        if not r["rationale"].strip():
            errors.append("%s: empty rationale" % where)

        cves = r["cve_ids"].split()
        for cve in cves:
            if not CVE_RE.match(cve):
                errors.append("%s: '%s' is not a CVE ID (CVE-YYYY-NNNN)" % (where, cve))
            elif not re.search(re.escape(cve) + r"(?!\d)", r["cve_source"]):
                errors.append("%s: %s is not cited by cve_source" % (where, cve))
        if cves and tid == "none":
            errors.append("%s: CVE IDs on a 'none' row: a rule that detects a CVE exploit maps to a technique" % where)
        for url in r["cve_source"].split():
            if not url.startswith(CVE_SOURCES):
                errors.append("%s: cve_source '%s' is not a cve.org or NVD record URL" % (where, url))
        if len(set(cves)) != len(cves):
            errors.append("%s: repeated CVE ID" % where)
        if r["cve_source"].strip() and not cves:
            errors.append("%s: cve_source given without cve_ids" % where)
        with_cve += bool(cves)

    if errors:
        for e in errors:
            print("  => " + e)
        print("check-attack: %d problem(s) in %s" % (len(errors), os.path.relpath(args.mapping, ROOT)))
        return 1

    mapped = len(rows) - per_technique["none"]
    print("ATT&CK Enterprise %s: %d rules, %d mapped to a technique, %d 'none', %d with CVE IDs"
          % (version, len(rows), mapped, per_technique["none"], with_cve))
    print("  confidence: " + ", ".join("%s %d" % (c, per_confidence[c]) for c in CONFIDENCE))
    print("  tactics: " + ", ".join("%s %d" % kv for kv in sorted(per_tactic.items(), key=lambda kv: (-kv[1], kv[0]))))
    print("All %d rules/*.xml have exactly one valid row in rules/mitre-attack.csv" % len(rule_files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
