#!/usr/bin/env python3
"""Run from any directory: python tools/check_ai_connection.py.

Uses backend .env; GET /models only, no generation or scan-data sharing.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ai_diagnostics import check_ai_connection

if __name__ == '__main__':
    result = check_ai_connection()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['ready'] else 1)
