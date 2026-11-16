import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE1 = HERE.parent
sys.path.insert(0, str(STAGE1))
import stage_seed


def pin_pred(rels, mode):
    if mode != "b":
        raise ValueError(mode)
    base = stage_seed.build_pred(rels, "seed_core")
    out = []
    for line in base.splitlines():
        m = re.match(r"^(\s+)(o\d+) in (o\d+)\.rf$", line)
        if m:
            line = f"{m.group(1)}{m.group(2)} in {m.group(3)}.rf.*(ddi.rf)"
        out.append(line)
    return "\n".join(out)


