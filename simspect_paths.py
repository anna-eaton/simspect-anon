from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).parent.resolve()

ALLOY_STAGE        = ROOT / "STAGE1_alloy"
MODELS_DIR         = ALLOY_STAGE / "models"
STAGE2_DIR         = ROOT / "STAGE2_compilation"
STAGE3_DIR         = ROOT / "STAGE3_gem5"
RUNCONFIGS         = ROOT / "runconfigs"
INSTRUCTION_TABLES = STAGE2_DIR / "instruction_tables" / "fv4_vocab.json"

TESTSETS = ROOT / "testsets"
RESULTS  = ROOT / "results"

JOBS_DIR      = ROOT / "jobs"
JOBS_MANIFEST = JOBS_DIR / "manifest.jsonl"
JOBS_LOGS     = JOBS_DIR / "logs"


def resolve(cfg_value, base: Path = ROOT) -> Path:
    p = Path(cfg_value)
    return p if p.is_absolute() else (base / p).resolve()
