import argparse, datetime as dt, json, os, random, re, shutil, subprocess, sys, time, traceback
from pathlib import Path

MODES = ["mispredict_not_taken", "mispredict_taken"]
ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "STAGE1_alloy/gen"))
import stream_fp


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def acopy(src, dst):
    tmp = dst.parent / f".{dst.name}.tmp"; shutil.copy2(src, tmp); os.replace(tmp, dst)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True); ap.add_argument("--cfg", required=True); ap.add_argument("--ts", required=True)
    ap.add_argument("--final", required=True); ap.add_argument("--ws", required=True); ap.add_argument("--jobs", type=int, default=24)
    ap.add_argument("--seed", type=int, default=20261109); ap.add_argument("--prefix", type=int, default=4000)
    ap.add_argument("--chunk", type=int, default=1500); ap.add_argument("--shard-size", type=int, default=20)
    a = ap.parse_args()
    src, ts, ws = Path(a.src), Path(a.ts), Path(a.ws); ws.mkdir(parents=True, exist_ok=True)
    base_name = a.final + "_base"; base = ts / base_name; final = ts / a.final
    (base / "xml").mkdir(parents=True, exist_ok=True)
    for m in MODES:
        for d in ("asm", "ann"):
            (final / m / d).mkdir(parents=True, exist_ok=True)
    (final / "xml").mkdir(parents=True, exist_ok=True)
    logf = open(ws / "restream.log", "a", buffering=1)
    def log(msg):
        logf.write(f"{now()} {msg}\n"); print(msg, flush=True)
    stf = ws / "state.json"
    st = json.loads(stf.read_text()) if stf.exists() else {"published": [], "tries": {}, "chunk": 0}
    def save():
        tmp = ws / ".state.json.tmp"; tmp.write_text(json.dumps(st)); os.replace(tmp, stf)
    txt = Path(a.cfg).read_text()
    txt = re.sub(r'"testset_dir"\s*:\s*"[^"]*"', f'"testset_dir": "{ts}"', txt, count=1)
    txt = re.sub(r'"jobs"\s*:\s*\d+', f'"jobs": {a.jobs}', txt, count=1)
    scfg = ws / "stage2_A_restream.json"
    scfg.write_text(txt)
    stems = sorted(p.stem for p in src.glob("inst-*.xml"))
    pairs = sorted((m, s) for m in MODES for s in stems)
    random.Random(a.seed).shuffle(pairs)
    order, seen = [], set()
    for m, s in pairs:
        if s not in seen:
            seen.add(s); order.append(s)
    pre = {s for _, s in pairs[:a.prefix]}
    first = [s for s in order if s in pre]
    (ws / "prefix_pairs.tsv").write_text("".join(f"{m}\t{s}\n" for m, s in pairs[:a.prefix]))
    (ws / "order_seed_pairs.tsv").write_text("".join(f"{i}\t{m}\t{s}\n" for i, (m, s) in enumerate(pairs)))
    log(f"START src={src} stems={len(stems)} pairs={len(pairs)} seed={a.seed} prefix {a.prefix} pairs = {len(pre)} stems; cfg={scfg} "
        f"final={final} published so far {len(st['published'])}")
    man = final / "MANIFEST.tsv"
    if not man.exists():
        man.write_text("stem\tchunk\tmodes\tpublished_at\n")
    pub = set(st["published"])
    rest = [s for s in order if s not in pre]
    chunks = [first] + [rest[i:i + a.chunk] for i in range(0, len(rest), a.chunk)]
    pending = []
    for ci, ch in enumerate(chunks):
        todo = [s for s in ch if s not in pub]
        if not todo and not pending:
            continue
        t0 = time.time()
        for s in todo:
            for ext in (".xml", ".txt"):
                p = src / f"{s}{ext}"
                if p.exists() and not (base / "xml" / p.name).exists():
                    shutil.copy2(p, base / "xml" / p.name)
        r = subprocess.run([sys.executable, "STAGE1_alloy/gen/stage2_sharded.py", "--config", str(scfg), "--model", base_name,
                            "--jobs", str(a.jobs), "--shard-size", str(a.shard_size)], capture_output=True, text=True)
        log(f"chunk {ci}: stage2 rc={r.returncode} stems {len(todo)} (+{len(pending)} retried) secs={round(time.time() - t0)}"
            + (f"\nSTDERR {r.stderr[-3000:]}" if r.returncode else ""))
        cand = pending + todo; pending = []; ready, partial = [], {}
        for s in cand:
            have = [m for m in MODES if (base / m / "asm" / f"{s}.s").exists() and (base / m / "ann" / f"{s}.ann.json").exists()]
            if len(have) == len(MODES):
                ready.append(s)
            else:
                st["tries"][s] = st["tries"].get(s, 0) + 1
                if st["tries"][s] >= 2 or ci == len(chunks) - 1:
                    ready.append(s); partial[s] = have
                    log(f"chunk {ci}: {s} published with modes {have} after {st['tries'][s]} Stage-2 passes")
                else:
                    pending.append(s)
        try:
            bd = ws / "batches" / f"c{ci:03d}"; shutil.rmtree(bd, ignore_errors=True); bd.mkdir(parents=True)
            stream_fp.vocab_rows(base, bd, ready)
            for m in MODES:
                for s in ready:
                    if s in partial and m not in partial[s]:
                        continue
                    acopy(base / m / "asm" / f"{s}.s", final / m / "asm" / f"{s}.s")
                for s in ready:
                    if s in partial and m not in partial[s]:
                        continue
                    acopy(base / m / "ann" / f"{s}.ann.json", final / m / "ann" / f"{s}.ann.json")
            for s in ready:
                for ext in (".xml", ".txt"):
                    p = base / "xml" / f"{s}{ext}"
                    if p.exists():
                        acopy(p, final / "xml" / p.name)
            keep = set(ready)
            for t, dst in (("rmw/rmw_stems.tsv", "rmw_stems.tsv"), ("jmp_rows/jmp_stems.tsv", "jmp_stems.tsv")):
                lines = (bd / t).read_text().splitlines(); agg = final / dst
                old = agg.read_text() if agg.exists() else (lines[0] + "\n")
                body = [l for l in lines[1:] if l.split("\t")[1] in keep]
                tmp = agg.parent / f".{agg.name}.tmp"; tmp.write_text(old + "".join(l + "\n" for l in body)); os.replace(tmp, agg)
            tp = now()
            rows = "".join(f"{s}\tc{ci:03d}\t{','.join(partial.get(s, MODES))}\t{tp}\n" for s in ready)
            tmp = man.parent / ".MANIFEST.tsv.tmp"; tmp.write_text(man.read_text() + rows); os.replace(tmp, man)
            st["published"] += ready; pub |= keep; st["chunk"] = ci; save()
            log(f"chunk {ci}: published {len(ready)} stems ({len(partial)} partial), total {len(pub)}/{len(stems)}")
        except Exception:
            log(f"chunk {ci}: PUBLISH ERROR\n{traceback.format_exc()}"); raise
    n = {m: len(list((final / m / "asm").glob("*.s"))) for m in MODES}
    full = all(n[m] == len(stems) for m in MODES)
    (final / "READY").write_text(f"READY {now()} restream: {a.final} = re-concretized programs ({len(stems)} stems from {src}) "
                                 f"re-concretized with {a.cfg} (recipe A, vocab_rj, no post-passes). tests {n}. seed-{a.seed} prefix {a.prefix} identical to "
                                 f"Nov 10's pair set: {full} (every stem compiled in both modes).\n")
    log(f"READY: tests {n}; full pair set {full}")


if __name__ == "__main__":
    main()
