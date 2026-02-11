from pathlib import Path
import sys

import yaml

def main() -> int:
    detections_dir = Path("detections")
    if not detections_dir.exists():
        print("No detections/ directory found. Skipping YAML validation.")
        return 0

    files = sorted(detections_dir.rglob("*.yml")) + sorted(detections_dir.rglob("*.yaml"))
    if not files:
        print("No detection YAML files found. Skipping YAML validation.")
        return 0

    failed = False
    for f in files:
        try:
            content = f.read_text(encoding="utf-8")
            yaml.safe_load(content)
            print(f"OK: {f}")
        except Exception as e:
            failed = True
            print(f"FAIL: {f} -> {e}")

    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())
