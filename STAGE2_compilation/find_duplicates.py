
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Hashable, List, Tuple

sys.path.insert(0, str(Path(__file__).parent))


def canonicalize(result: Dict[str, Any], inst: Any = None) -> Tuple:
    reg_canon: Dict[str, str] = {}
    mem_canon: Dict[str, str] = {}

    def canon_state(raw: str | None) -> str | None:
        if raw is None:
            return None
        if raw.startswith("Reg_s"):
            if raw not in reg_canon:
                reg_canon[raw] = f"r{len(reg_canon)}"
            return reg_canon[raw]
        if raw.startswith("Mem_s"):
            if raw not in mem_canon:
                mem_canon[raw] = f"m{len(mem_canon)}"
            return mem_canon[raw]
        return raw

    atom_to_slot: Dict[str, Tuple] = {}
    instr_fingerprints: List[Tuple] = []
    for rec in result["instructions"]:
        slot_parts: List[Tuple] = []
        for slot_type, slot_list in rec["slots"].items():
            for entry in slot_list:
                slot_parts.append((slot_type, canon_state(entry.get("physical"))))
                if entry.get("operand_atom"):
                    atom_to_slot[entry["operand_atom"]] = (rec["pc"], entry["slot"])
        instr_fingerprints.append((
            rec["kind"],
            rec["resolved"],
            rec["committed"],
            tuple(slot_parts),
        ))

    ddi_fp: Tuple = ()
    rf_fp: Tuple = ()
    if inst is not None:
        ddi_fp = tuple(sorted(
            (atom_to_slot[s], atom_to_slot[d])
            for s, d in inst.fields.get("ddi", [])
            if s in atom_to_slot and d in atom_to_slot
        ))
        rf_fp = tuple(sorted(
            (atom_to_slot[s], atom_to_slot[d])
            for s, d in inst.fields.get("rf", [])
            if s in atom_to_slot and d in atom_to_slot
        ))

    ru = result["resource_usage"]
    return (
        tuple(instr_fingerprints),
        ru["register_count"],
        ru["memory_count"],
        ddi_fp,
        rf_fp,
    )


