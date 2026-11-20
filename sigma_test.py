"""
Test Sigma rules against a web access log (Apache combined format).
Usage: python sigma_test.py access.log
Supports the simple rules made by sigma_gen.py: startswith/endswith/contains
matches, plus event_count correlation rules (requests per client per window).
"""
import glob
import re
import sys
from collections import defaultdict
from datetime import datetime

import yaml

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')

FIELD_MAP = {"c-uri": "uri", "cs-user-agent": "ua", "cs-method": "method",
             "c-ip": "ip"}


def rule_matches(selection, event):
    for key, values in selection.items():
        field, _, modifier = key.partition("|")
        text = event[FIELD_MAP[field]].lower()
        values = values if isinstance(values, list) else [values]
        ok = False
        for v in values:
            v = str(v).lower()
            if modifier == "startswith" and text.startswith(v):
                ok = True
            elif modifier == "endswith" and text.endswith(v):
                ok = True
            elif modifier == "contains" and v in text:
                ok = True
            elif modifier == "" and text == v:
                ok = True
        if not ok:
            return False
    return True


def parse_timespan(text):
    unit = {"s": 1, "m": 60, "h": 3600}[text[-1]]
    return int(text[:-1]) * unit


def max_in_window(times, window):
    """Largest number of events inside any window of 'window' seconds."""
    times.sort()
    best, left = 0, 0
    for right, t in enumerate(times):
        while (t - times[left]).total_seconds() >= window:
            left += 1
        best = max(best, right - left + 1)
    return best


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python sigma_test.py access.log")
    events = []
    with open(sys.argv[1]) as f:
        for line in f:
            m = LOG_RE.match(line)
            if m:
                e = m.groupdict()
                e["dt"] = datetime.strptime(e["time"], "%d/%b/%Y:%H:%M:%S %z")
                events.append(e)
    print(f"Log lines parsed: {len(events)}\n")

    rules = []
    for path in sorted(glob.glob("rules/*.yml")):
        with open(path) as f:
            rules.append(yaml.safe_load(f))
    by_name = {r["name"]: r for r in rules if "name" in r}
    helpers = {n for r in rules if "correlation" in r
               for n in r["correlation"]["rules"]}

    passed = total = 0
    for rule in rules:
        if rule.get("name") in helpers:
            continue  # helper rules are not tested on their own
        total += 1
        if "correlation" in rule:
            corr = rule["correlation"]
            base = by_name[corr["rules"][0]]
            sel = base["detection"]["selection"]
            groups = defaultdict(list)
            for e in events:
                if rule_matches(sel, e):
                    groups[e["ip"]].append(e["dt"])
            window = parse_timespan(corr["timespan"])
            need = corr["condition"]["gte"]
            peak = max((max_in_window(t, window) for t in groups.values()), default=0)
            ok = peak >= need
            print(f"[{'PASS' if ok else 'FAIL'}] {rule['title']}")
            print(f"        peak {peak} requests in {corr['timespan']} from one client (threshold {need})")
        else:
            sel = rule["detection"]["selection"]
            hits = [e for e in events if rule_matches(sel, e)]
            ok = bool(hits)
            print(f"[{'PASS' if ok else 'FAIL'}] {rule['title']}  ({len(hits)} matching requests)")
            if hits:
                print(f"        example: {hits[0]['method']} {hits[0]['uri']} -> {hits[0]['status']}")
        passed += ok
    print(f"\n{passed} of {total} rules fired on real traffic.")


if __name__ == "__main__":
    main()
