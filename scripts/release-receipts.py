#!/usr/bin/env python3
"""Collect only direct successful producer-job outputs, never payload manifests."""

import importlib.util
import json
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location("artifacts", Path(__file__).with_name("release-artifacts.py"))
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)
needs = json.loads(os.environ["PRODUCERS"])
if any(job["result"] != "success" for job in needs.values()):
    raise SystemExit("producer did not succeed")
receipts = [job["outputs"] for job in needs.values()]
artifacts.validate_receipts(receipts)
with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as output:
    output.write("receipts=" + json.dumps(receipts, separators=(",", ":")) + "\n")
