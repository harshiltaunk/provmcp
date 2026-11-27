"""Convert InjecAgent test cases into ProvMCP multi-server scenarios.

    git clone https://github.com/uiuc-kang-lab/InjecAgent.git ~/Projects/InjecAgent
    python scripts/import_injecagent.py --repo ~/Projects/InjecAgent
    python scripts/import_injecagent.py --repo ~/Projects/InjecAgent --inspect

Writes one JSON scenario per test case to benchmarks/external/injecagent/
(git-ignored; rerun this script to regenerate) plus _manifest.json.
InjecAgent is MIT-licensed; see its LICENCE file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from provmcp.importers.injecagent import (
    InjecAgentFormatError,
    find_case_files,
    import_repo,
    load_cases,
)


def inspect(repo: Path, settings: list[str]) -> int:
    files = find_case_files(repo, settings)
    if not files:
        print(f"No test_cases_*_{{{','.join(settings)}}}.json found under {repo}")
        return 1
    for kind, setting, path in files:
        cases = load_cases(path)
        print(f"{path.name}: {len(cases)} case(s), kind={kind}, setting={setting}")
        if cases:
            print("  keys:", sorted(cases[0]))
            print("  first case:", json.dumps(cases[0], ensure_ascii=False)[:600], "...")
    tools = repo / "data" / "tools.json"
    print(f"tools catalog: {tools if tools.is_file() else 'not found (heuristic split)'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, required=True, help="path to the InjecAgent clone")
    parser.add_argument("--out", type=Path, default=Path("benchmarks/external/injecagent"))
    parser.add_argument("--settings", default="base,enhanced")
    parser.add_argument("--tools-json", type=Path, default=None)
    parser.add_argument("--inspect", action="store_true", help="print the file format and exit")
    args = parser.parse_args()
    repo = args.repo.expanduser()
    settings = [s.strip() for s in args.settings.split(",") if s.strip()]
    if args.inspect:
        return inspect(repo, settings)
    try:
        report = import_repo(repo, args.out, settings=settings, tools_json=args.tools_json)
    except InjecAgentFormatError as exc:
        print(f"Import failed: {exc}", file=sys.stderr)
        print("Run again with --inspect and send the output.", file=sys.stderr)
        return 1
    print(f"Wrote {report.written} scenario(s) to {args.out}")
    for name, count in report.by_file.items():
        print(f"  {name}: {count}")
    print(f"  cross-server: {report.cross_server}   same-server: {report.same_server}")
    print(f"  toolkit split: {report.toolkit_split}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
