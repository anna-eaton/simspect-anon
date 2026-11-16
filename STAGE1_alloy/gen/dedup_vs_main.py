import argparse, json, sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, ".")
sys.path.insert(0, "scripts")
import alloy_solver_order as aso
FP = None


def _fp(p):
    global FP
    if FP is None:
        FP = aso.make_fingerprinter(Path("STAGE2_compilation"))
    try:
        return p.stem, FP(p)
    except Exception as e:
        return p.stem, f"ERROR {e}"


def fps(d, jobs):
    with ProcessPoolExecutor(jobs) as ex:
        return dict(ex.map(_fp, sorted(Path(d).glob("inst-*.xml")), chunksize=50))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--main", required=True); ap.add_argument("--extra", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--jobs", type=int, default=8); a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    m, x = fps(a.main, a.jobs), fps(a.extra, a.jobs)
    mset = {v for v in m.values() if not v.startswith("ERROR")}
    dup = sorted(s for s, v in x.items() if v in mset)
    (out / "dup_stems.txt").write_text("".join(s + "\n" for s in dup))
    summ = dict(main_programs=len(m), main_fp_errors=sum(v.startswith("ERROR") for v in m.values()), extra_programs=len(x),
                extra_fp_errors=sum(v.startswith("ERROR") for v in x.values()), extra_duplicates_of_main=len(dup),
                extra_unique=len(x) - len(dup))
    (out / "dedup_summary.json").write_text(json.dumps(summ, indent=1)); print(json.dumps(summ))


if __name__ == "__main__":
    main()
