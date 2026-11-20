"""
Verify fixes: compare a 'before' scan with an 'after' scan.
Usage: python verify.py before.json after.json
"""
import json
import sys

def load(path):
    with open(path) as f:
        return {item["id"]: item for item in json.load(f)}

def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python verify.py before.json after.json")
    before, after = load(sys.argv[1]), load(sys.argv[2])

    fixed = [before[i] for i in before if i not in after]
    remaining = [after[i] for i in after if i in before]
    new = [after[i] for i in after if i not in before]

    rate = round(100 * len(fixed) / len(before)) if before else 0

    lines = ["# Fix Verification Report", "",
             f"- Findings before: {len(before)}",
             f"- Fixed (confirmed by re-scan): {len(fixed)}",
             f"- Still open: {len(remaining)}",
             f"- New after fix: {len(new)}",
             f"- Fix rate: {rate}%", ""]
    for title, items in (("Fixed", fixed), ("Still open", remaining), ("New", new)):
        lines.append(f"## {title}")
        lines += [f"- [{x['severity']}] {x['title']}" for x in items] or ["- none"]
        lines.append("")

    report = "\n".join(lines)
    print(report)
    with open("verify_report.md", "w") as f:
        f.write(report)
    print("Saved to verify_report.md")

if __name__ == "__main__":
    main()
