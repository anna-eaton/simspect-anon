import argparse
import hashlib
import json
import re
from pathlib import Path

SCOPE_RE = re.compile(r"(\}\s*for 9 but )6( Instruction, exactly 1 rBool, exactly 1 cBool, exactly 1 tBool)")
LEAK_RE = re.compile(r"^fun leakage_function\s*:\s*Operand\s*\{(.*)\}", re.M)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("core")
    ap.add_argument("out_dir")
    ap.add_argument("--split-from", type=int, default=5,
                    help="exact sizes >= this are split by transmitter kind")
    a = ap.parse_args()
    src = Path(a.core).read_text()
    if len(SCOPE_RE.findall(src)) != 1:
        raise SystemExit("refusing: expected exactly one `for 9 but 6 Instruction, ...` run scope")
    m = LEAK_RE.search(src)
    if not m:
        raise SystemExit("refusing: no leakage_function line")
    kinds = sorted(set(re.findall(r"\b(Loads|Stores|Branchxs|Otherxs)\b", m.group(1))))
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(a.core).stem
    parts = []

    def emit(name, k, fact, desc):
        body = SCOPE_RE.sub(lambda mm: f"{mm.group(1)}exactly {k}{mm.group(2)}", src)
        if fact:
            body = body + f"\nfact stage1_partition {{ {fact} }}\n"
        p = out / f"{stem}__{name}.als"
        p.write_text(body)
        parts.append({"name": name, "k": k, "fact": fact, "desc": desc,
                      "file": p.name, "sha256": sha(p)})

    for k in range(1, 7):
        if k < a.split_from:
            emit(f"k{k}", k, None, f"exactly {k} instructions, any transmitter")
            continue
        for kind in kinds:
            emit(f"k{k}_{kind}", k, f"xm in {kind}", f"exactly {k} instructions, transmitter in {kind}")
        emit(f"k{k}_rest", k, f"xm not in ({' + '.join(kinds)})",
             f"exactly {k} instructions, transmitter in none of {kinds} (expected UNSAT: coverage check)")
    (out / "partitions.json").write_text(json.dumps({
        "source": str(a.core), "source_sha256": sha(a.core), "kinds": kinds,
        "split_from": a.split_from,
        "coverage": "k=1..6 exact sizes cover `but 6`; per split size the kinds plus `rest` cover every xm; pairwise disjoint",
        "partitions": parts}, indent=2))
    print(f"{stem}: {len(parts)} partitions, kinds {kinds} -> {out}")


if __name__ == "__main__":
    main()
