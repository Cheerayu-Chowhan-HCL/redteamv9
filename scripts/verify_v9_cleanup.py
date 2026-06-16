"""
verify_v9_cleanup.py - RedTeam V9 contamination verification.
Checks active runtime/config/instruction files for stale V6/V7 paths and labels.
"""
from pathlib import Path
import re
import sys

ROOT = Path("C:/Users/chirayu/redteamv9")
CHECK_DIRS = ["tools", "scripts", "core", "servers", "web", "cowork", "skills", "aex"]
CHECK_FILES = ["README.md", "DEMO_START.ps1", "clean_start.ps1", "start_v6.ps1"]

EXCLUDED_NAMES = {
    "verify_v9_cleanup.py",
}
EXCLUDED_PATTERNS = (
    re.compile(r"cowork[\\/].*_(?:v6|v7|testfire|altroj).*_report\.html$", re.I),
    re.compile(r"cowork[\\/]pentest_.*summary\.md$", re.I),
    re.compile(r"cowork[\\/]pentest-report-quality_report\.html$", re.I),
)

BAD_PATTERNS = [
    "C:/users/chirayu/redteam" + "v7",
    "C:/Users/chirayu/redteam" + "v7",
    "C:\\users\\chirayu\\redteam" + "v7",
    "C:\\Users\\chirayu\\redteam" + "v7",
    "redteam" + "v7.db",
    "redteam-" + "v7",
    "rt" + "v7_bearer",
    "rt" + "v6_sandbox",
    "Use redteam-" + "v7 MCP tools",
]


def is_excluded(path: Path) -> bool:
    rel = str(path.relative_to(ROOT))
    return (
        path.name in EXCLUDED_NAMES
        or "__pycache__" in path.parts
        or any(p.search(rel) for p in EXCLUDED_PATTERNS)
    )


def iter_files():
    for dirname in CHECK_DIRS:
        base = ROOT / dirname
        if base.exists():
            for path in base.rglob("*"):
                if path.is_file() and not is_excluded(path):
                    yield path
    for filename in CHECK_FILES:
        path = ROOT / filename
        if path.exists():
            yield path


def main() -> int:
    failures = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            failures.append((path, f"read failed: {exc}"))
            continue
        for bad in BAD_PATTERNS:
            if bad in text:
                failures.append((path, bad))

    print()
    print("=" * 58)
    print("  RedTeam V9 - Contamination Verification")
    print("=" * 58)
    if failures:
        for path, bad in failures:
            print(f"  FAIL {path.relative_to(ROOT)}: {bad}")
        print()
        print(f"  Overall: FAIL ({len(failures)} stale references)")
        return 1

    print("  Runtime/config/instruction references: PASS")
    print("  Historical report artifacts: excluded by design")
    print("  Overall: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
