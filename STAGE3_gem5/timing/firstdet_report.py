import argparse, collections, json, random, sys
from pathlib import Path

BUGS = {"UV1": "invisispec", "UV3": "cleanupspec", "UV4": "cleanupspec", "UV5": "cleanupspec", "UV6": "speclfb",
        "jmp_shadow": "speclfb"}
MODES = ["mispredict_not_taken", "mispredict_taken"]


def jl(p: Path):
    if not p.exists():
        return []
    out = []
    for l in p.read_text().splitlines():
        try:
            out.append(json.loads(l))
        except Exception:
            pass
    return out


def seed_order(testset: Path, seed: int):
    pairs = []
    for m in MODES:
        a = {p.stem for p in (testset / m / "asm").glob("inst-*.s")}
        n = {p.name[:-len(".ann.json")] for p in (testset / m / "ann").glob("inst-*.ann.json")}
        pairs += [(m, s) for s in sorted(a & n)]
    pairs.sort()
    random.Random(seed).shuffle(pairs)
    return pairs


def defense_rows(d: Path, defense: str, testset: Path = None, guard=True, snapshot_cut=True):
    rows = {r["idx"]: r for r in jl(d / "results.jsonl")}
    dropped = collections.Counter()
    if testset is not None and guard:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import firstdet_stream as fs
        shas = {}
        osf = d / "order_stream.tsv"
        if osf.exists():
            for l in osf.read_text().splitlines():
                f = l.split("\t")
                if len(f) >= 4:
                    shas[int(f[0])] = f[3]
        for i in list(rows):
            r = rows[i]
            sp = testset / r["mode"] / "asm" / f"{r['stem']}.s"
            ap_ = testset / r["mode"] / "ann" / f"{r['stem']}.ann.json"
            try:
                cur = fs.file_sha(sp, ap_)
                ok, _ = fs.provenance_ok(json.loads(ap_.read_text()))
            except Exception:
                dropped["file_gone"] += 1; del rows[i]; continue
            if i in shas and shas[i] != cur:
                dropped["changed_after_run"] += 1; del rows[i]; continue
            if not ok:
                dropped["provenance_guard"] += 1; del rows[i]; continue
    cls = {r["idx"]: set(r["sigs"]) for r in jl(d / "classes.jsonl")}
    if defense == "cleanupspec" and (d / "classes_rmw.jsonl").exists():
        cls = {r["idx"]: set(r["sigs"]) for r in jl(d / "classes_rmw.jsonl")}
    order_lines = [r["idx"] for r in jl(d / "results.jsonl")] if snapshot_cut else []
    cut = None
    for k, i in enumerate(order_lines):
        r = rows.get(i)
        if r is not None and r.get("hit") and (i not in cls or cls[i] <= {"no_evidence"}):
            cut = k
            break
    if cut is not None:
        late = set(order_lines[cut:])
        n0 = len(rows)
        rows = {i: r for i, r in rows.items() if i not in late}
        dropped["after_classify_snapshot"] = n0 - len(rows)
    if not snapshot_cut:
        pend = [i for i, r in rows.items() if r.get("hit") and (i not in cls or cls[i] <= {"no_evidence"})]
        for i in pend:
            del rows[i]
        dropped["pending_classification"] = len(pend)
    cls = {i: v for i, v in cls.items() if i in rows}
    return rows, cls, dict(dropped)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--invisispec"); ap.add_argument("--cleanupspec"); ap.add_argument("--speclfb")
    ap.add_argument("--testset", required=True)
    ap.add_argument("--seed", type=int, default=20261109)
    ap.add_argument("--gen-cpu-per-test", type=float, default=None,
                    help="amortized Alloy + Stage 2 CPU-s per corpus test; omitted = execution only")
    ap.add_argument("--no-guard", action="store_true", help="skip the sha/provenance row filter")
    ap.add_argument("--sample", default="", help="per-defense uniform stem-hash subsample to score, e.g. "
                    "invisispec=0.25,speclfb=0.25 (firstdet_stream.in_sample); rows outside it are dropped")
    ap.add_argument("--rows", choices=["auto", "prefix", "all"], default="auto",
                    help="prefix = score only the longest seed-order prefix of the FULL corpus whose tests have all run "
                         "and been classified (the final semantics: first N of the seed-20261109 order); all = every "
                         "finished row (interim, streaming). auto = prefix when the testset has READY/DONE, else all")
    ap.add_argument("--prefix", default="", help="cap the prefix per defense, e.g. invisispec=4000,speclfb=4000")
    ap.add_argument("--json"); ap.add_argument("--md")
    args = ap.parse_args()
    gen_src = "--gen-cpu-per-test" if args.gen_cpu_per_test is not None else None
    order = seed_order(Path(args.testset), args.seed)
    pos = {p: i for i, p in enumerate(order)}
    dirs = {"invisispec": args.invisispec, "cleanupspec": args.cleanupspec, "speclfb": args.speclfb}
    res = {"generated_utc": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
           "corpus_pairs_now": len(order), "seed": args.seed, "gen_cpu_per_test": args.gen_cpu_per_test, "gen_cpu_source": gen_src,
           "defenses": {}, "bugs": {}}
    for dfn, dd in dirs.items():
        if not dd:
            continue
        d = Path(dd)
        mode_rows = args.rows if args.rows != "auto" else (
            "prefix" if any((Path(args.testset) / f).exists() for f in ("READY", "DONE")) else "all")
        rows, cls, dropped = defense_rows(d, dfn, Path(args.testset), not args.no_guard,
                                          snapshot_cut=(mode_rows == "all"))
        if mode_rows == "prefix":
            have = {(r["mode"], r["stem"]): i for i, r in rows.items()}
            L = 0
            cap = dict((kv.split("=")[0], int(kv.split("=")[1])) for kv in args.prefix.split(",") if "=" in kv).get(dfn)
            while L < len(order) and order[L] in have and (cap is None or L < cap):
                L += 1
            keep = {have[p] for p in order[:L]}
            dropped["outside_seed_prefix"] = len(rows) - len(keep)
            rows = {i: r for i, r in rows.items() if i in keep}
            cls = {i: v for i, v in cls.items() if i in rows}
        frac = dict((kv.split("=")[0], float(kv.split("=")[1])) for kv in args.sample.split(",") if "=" in kv).get(dfn, 1.0)
        if frac < 1:
            import firstdet_stream as fs
            n0 = len(rows)
            rows = {i: r for i, r in rows.items() if fs.in_sample(r["stem"], frac)}
            cls = {i: v for i, v in cls.items() if i in rows}
            dropped["outside_sample_%g" % frac] = n0 - len(rows)
        N = len(rows)
        if not N:
            continue
        cpu_t = sum(r.get("total_cpu_s") or 0 for r in rows.values())
        cpu_g = sum(r.get("gem5_cpu_s") or 0 for r in rows.values())
        unclassified_hits = sum(1 for i, r in rows.items() if r.get("hit") and i not in cls)
        setups = collections.Counter(r.get("cache_setup") or "warm" for r in rows.values())
        status = collections.Counter(r.get("status") for r in rows.values())
        run_seed = sorted((pos.get((r["mode"], r["stem"]), 10**12), i) for i, r in rows.items())
        seed_rank = {i: k + 1 for k, (_, i) in enumerate(run_seed)}
        allsigs = collections.Counter(s for v in cls.values() for s in v)
        res["defenses"][dfn] = dict(dir=str(d), N=N, rows_mode=mode_rows, dropped=dropped, hits=sum(1 for r in rows.values() if r.get("hit")),
                                    unclassified_hits=unclassified_hits, status=dict(status),
                                    cache_setups=dict(setups), total_cpu_s_per_test=round(cpu_t / N, 3),
                                    gem5_cpu_s_per_test=round(cpu_g / N, 3), all_signatures=dict(allsigs),
                                    all_corpus_pairs_run=len(rows) >= len(order))
        for bug, bd in BUGS.items():
            if bd != dfn:
                continue
            det = [i for i, s in cls.items() if bug in s and i in rows]
            K = len(det)
            exp = (N + 1) / (K + 1)
            first_seed = min((seed_rank[i] for i in det), default=None)
            fs_i = min(det, key=lambda i: seed_rank[i]) if det else None
            first_stream = (min(det) + 1) if det else None
            per_test = cpu_t / N + (args.gen_cpu_per_test or 0)
            res["bugs"][bug] = dict(
                defense=dfn, K=K, N=N, expected_tests=round(exp, 2),
                censored=(K == 0),
                first_seed_order=first_seed,
                first_seed_stem=(f"{rows[fs_i]['mode']}/{rows[fs_i]['stem']}" if fs_i is not None else None),
                first_stream_order=first_stream,
                det_setups=dict(collections.Counter(rows[i].get("cache_setup") or "warm" for i in det)),
                simspect_cpu_s_per_test=round(per_test, 3),
                simspect_expected_cpu_s=round(exp * per_test, 1),
                simspect_expected_cpu_s_exec_only=round(exp * cpu_t / N, 1))
    js = json.dumps(res, indent=1)
    if args.json:
        Path(args.json).write_text(js)
    modes_used = sorted({v.get("rows_mode") for v in res["defenses"].values()})
    lines = [("**Rows: seed-20261109 order prefix of the full corpus (final semantics), longest fully run and classified prefix per defense.**"
              if modes_used == ["prefix"] else
              "**INTERIM: all classified tests so far (completion order, snapshot-consistent), not the final seed-order prefix.**")
             + f" Report {res['generated_utc']}; N per defense: "
             + ", ".join(f"{k} {v['N']}" for k, v in res["defenses"].items()) + "\n",
             "| bug | defense | K/N | expected tests (N+1)/(K+1) | first (seed order / stream) | setups of detecting tests | SimSpect exp. CPU-s |",
             "|---|---|---|---|---|---|---|"]
    for b, v in res["bugs"].items():
        gt = ">" if v["censored"] else ""
        lines.append(f"| {b} | {v['defense']} | {v['K']}/{v['N']} | {gt}{v['expected_tests']} | "
                     f"{v['first_seed_order'] or '—'} / {v['first_stream_order'] or '—'} | {v['det_setups']} | "
                     f"{gt}{v['simspect_expected_cpu_s']} |")
    md = "\n".join(lines)
    if args.md:
        Path(args.md).write_text(md + "\n")
    print(js)
    print(md)


if __name__ == "__main__":
    main()
