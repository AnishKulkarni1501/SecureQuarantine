import argparse
import json
from pathlib import Path

from app.evaluation import run_ablation


parser = argparse.ArgumentParser(description="Compute A/B/C/D SecureQuarantine ablation metrics from family-split JSONL test records.")
parser.add_argument("dataset", type=Path, help="JSONL file with only split=test records")
args = parser.parse_args()
records = [json.loads(line) for line in args.dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
print(json.dumps(run_ablation(records), indent=2))
