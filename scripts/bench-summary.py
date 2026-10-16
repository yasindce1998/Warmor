#!/usr/bin/env python3
"""Summarise Go benchmark output run with -count N.

For every benchmark name and metric, prints the median over the N runs and
the min-max range, e.g.

    scripts/bench-summary.py bench-results/kernel.txt

This is how the tables in docs/PERFORMANCE.md were derived from the raw
output. Standard library only.
"""

import re
import statistics
import sys
from collections import OrderedDict

LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+(.*)$")


def main() -> None:
    results: "OrderedDict[str, OrderedDict[str, list]]" = OrderedDict()
    for path in sys.argv[1:] or ["-"]:
        f = sys.stdin if path == "-" else open(path, encoding="utf-8")
        for line in f:
            m = LINE.match(line.strip())
            if not m:
                continue
            name, rest = m.group(1), m.group(3).split()
            metrics = results.setdefault(name, OrderedDict())
            for value, unit in zip(rest[0::2], rest[1::2]):
                try:
                    metrics.setdefault(unit, []).append(float(value))
                except ValueError:
                    pass
    for name, metrics in results.items():
        runs = max(len(v) for v in metrics.values())
        print(f"{name}  (n={runs})")
        for unit, vals in metrics.items():
            med = statistics.median(vals)
            print(f"    {unit:>16}  median {med:>14.1f}   range {min(vals):.1f} .. {max(vals):.1f}")


if __name__ == "__main__":
    main()
