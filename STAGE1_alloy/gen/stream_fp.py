import argparse, datetime as dt, hashlib, json, os, resource, shutil, subprocess, sys, time, traceback
from pathlib import Path

B = Path("work"); TS = B / "testsets"; WS = B / "ws"
STAGE1_LOGS = "stage1/logs/Footprint_6_u_core_ri__*.log"
MODES = ["mispredict_not_taken", "mispredict_taken"]


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def cpu_children():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def run_cpu(st, key, cmd, **kw):
    c0 = cpu_children(); r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    st.setdefault("cpu_s", {}); st["cpu_s"][key] = round(st["cpu_s"].get(key, 0) + cpu_children() - c0, 1)
    return r


def acopy(src, dst):
    tmp = dst.parent / f".{dst.name}.tmp"; shutil.copy2(src, tmp); os.replace(tmp, dst)


def vocab_rows(srcd, bd, stems):
    (bd / "rmw").mkdir(parents=True, exist_ok=True); (bd / "jmp_rows").mkdir(parents=True, exist_ok=True)
    if not (bd / "jmp").exists():
        os.symlink(srcd, bd / "jmp")
    rr, jr = [], []
    for m in MODES:
        for s in stems:
            p = srcd / m / "ann" / f"{s}.ann.json"
            if not p.exists():
                continue
            ann = json.loads(p.read_text()); v = ann.get("vocab_rj")
            if v is None:
                raise RuntimeError(f"{p} has no vocab_rj: Stage-2 config lacks fanout_v2.vocab_rj")
            x = ann.get("xmit") or {}
            if x.get("pc") in v.get("rmw_pcs", []):
                rr.append([m, s, "load_rmw_or0 (Stage 2)", str(x.get("addr_hex"))])
            for k in v.get("jmp_filler_before_pcs", []):
                jr.append([m, s, str(k), "", ""])
    (bd / "rmw" / "rmw_stems.tsv").write_text("mode\tstem\torig_instr\txmit_addr\n" + "".join("\t".join(r) + "\n" for r in rr))
    (bd / "jmp_rows" / "jmp_stems.tsv").write_text("mode\tstem\tbefore_pc\tjmp_addr\tn_candidates\n" + "".join("\t".join(r) + "\n" for r in jr))
    return True


def write_prov(final, st, s15, base, cfg, code, a, ready=False):
    s15l = s15 if isinstance(s15, list) else [s15]
    jobs = [json.loads(l) for d15 in s15l if (d15 / "jobs.jsonl").exists() for l in (d15 / "jobs.jsonl").read_text().splitlines() if l.strip()]
    s1 = {}
    s1f = WS / "stage1" / "status" / "stage1_status.json"
    pairs = sum(len(list((final / m / "ann").glob("*.ann.json"))) for m in MODES)
    prov = {"updated": now(), "complete": ready, "corpus": str(final), "programs_merged": len(st["order"]), "counts": st.get("counts"), "stems_published": len(st["published"]),
            "stem_mode_pairs": pairs, "batches": st["batch"],
            "cpu_s": {"stage1_alloy_cores": "see stage1_cpu_s (wall-clock of each single-threaded Stage-1 JVM partition)",
                      "stage15_alloy_job_wall_s_sum": round(sum(j.get("secs") or 0 for j in jobs), 1),
                      "stage15_note": "sum of per-job wall seconds of one JVM each (a6RandomModels is single-threaded apart from GC threads), all jobs incl. EXHAUSTED/0",
                      "stage2_parsexml_llc": st.get("cpu_s", {}).get("stage2"),
                      "stage2_note": "RUSAGE_CHILDREN deltas of the whole subprocess tree (user+sys CPU-s)"},
            "stage1_cpu_s": stage1_cpu(), "stage15": [str(x) for x in s15l], "stage15_seeds": {str(d15): json.loads((d15 / "QUEUE_ORDER.json").read_text()).get("shuffle_seed") if (d15 / "QUEUE_ORDER.json").exists() else None for d15 in s15l}, "base_testset": str(base), "stage2_config": str(cfg), "code": str(code),
            "recipe_version": "A (fanout_v2.vocab_rj: RMW and jmp drawn uniformly in Stage 2)",
            "code_hashes": {f: hashlib.sha256((code / f).read_bytes()).hexdigest() for f in
                            ("STAGE2_compilation/parsexml.py", "STAGE2_compilation/batch_generate.py", "runconfigs/stage2_A.json")
                            if (code / f).exists()},
            "stage2_config_sha256": hashlib.sha256(cfg.read_bytes()).hexdigest(),
            "stage15_logs_seed_start": {str(d15): next((l.split("seed_start=")[1].split()[0] for l in (d15 / "stage15lp.log").read_text().splitlines() if "seed_start=" in l), None) if (d15 / "stage15lp.log").exists() else None for d15 in s15l},
            "recipe": "stage2_A (fanout_v2.vocab_rj rmw+jmp, uniform draws)"}
    tmp = final / ".PROVENANCE.json.tmp"; tmp.write_text(json.dumps(prov, indent=1)); os.replace(tmp, final / "PROVENANCE.json")


def stage1_cpu():
    out = {}
    for lg in sorted(WS.glob(STAGE1_LOGS)):
        lines = lg.read_text(errors="replace").splitlines()
        try:
            t0 = dt.datetime.fromisoformat(lines[0].split()[0]); t1 = dt.datetime.fromisoformat(lines[-1].split()[0])
            v = [l.split("VERDICT=")[1].split()[0] for l in lines if "VERDICT=" in l]
            out[lg.stem] = {"wall_s": round((t1 - t0).total_seconds()), "verdict": v[-1] if v else "RUNNING"}
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--s15", required=True, nargs="+", help="one or more stage15lp out dirs (e.g. one per node)"); ap.add_argument("--base-name", required=True); ap.add_argument("--final-name", required=True)
    ap.add_argument("--cfg", required=True); ap.add_argument("--code", required=True)
    ap.add_argument("--ts-dir", default=None, help="testset root (default work/testsets)")
    ap.add_argument("--ws", default=None, help="work dir holding logs/ and stream/ (default work/ws)")
    ap.add_argument("--stage1-logs", default=None, help="glob (relative to --ws) of the Stage-1 partition logs, for the CPU-s record")
    ap.add_argument("--family-label", default="Footprint_6_u", help="family name written into READY")
    ap.add_argument("--interval", type=int, default=150); ap.add_argument("--jobs", type=int, default=16)
    ap.add_argument("--min-batch", type=int, default=50); ap.add_argument("--max-batch", type=int, default=150); 
    a = ap.parse_args()
    global TS, WS, STAGE1_LOGS
    TS = Path(a.ts_dir) if a.ts_dir else TS; WS = Path(a.ws).resolve() if a.ws else WS; STAGE1_LOGS = a.stage1_logs or STAGE1_LOGS
    (WS / "logs").mkdir(parents=True, exist_ok=True)
    s15s = [Path(x).resolve() for x in a.s15]; s15 = s15s[0]
    code, cfg = Path(a.code).resolve(), Path(a.cfg).resolve()
    base, final = TS / a.base_name, TS / a.final_name
    sd = WS / "stream" / a.final_name; sd.mkdir(parents=True, exist_ok=True); (base / "xml").mkdir(parents=True, exist_ok=True)
    final.mkdir(parents=True, exist_ok=True); (final / "xml").mkdir(exist_ok=True)
    for m in MODES:
        for d in ("asm", "ann"):
            (final / m / d).mkdir(parents=True, exist_ok=True)
    logf = open(WS / "logs" / f"stream_{a.final_name}.log", "a", buffering=1)
    def log(msg):
        logf.write(f"{now()} {msg}\n"); print(msg, flush=True)
    stf = sd / "state.json"
    st = json.loads(stf.read_text()) if stf.exists() else dict(merged_jobs=[], n=0, seen={}, info={}, published=[], tries={}, batch=0, order=[])
    if "order" not in st:
        st["order"] = [f"inst-{k:06d}" for k in range(1, st["n"] + 1)]
    def save():
        tmp = stf.with_suffix(".tmp"); tmp.write_text(json.dumps(st)); os.replace(tmp, stf)
    log(f"START s15={s15} base={base} final={final} cfg={cfg} interval={a.interval} jobs={a.jobs} (resume: n={len(st['order'])}, published={len(st['published'])})")
    smap = open(base / "xml" / "_stream_map.jsonl", "a", buffering=1)
    man = final / "MANIFEST.tsv"
    if not man.exists():
        man.write_text("stem\tcore\tseed\tmerged_at\tpublished_at\tbatch\tmodes\n")
    for t in ("rmw_stems.tsv", "jmp_stems.tsv"):
        if not (final / t).exists():
            (final / t).write_text("")
    while True:
        t_cycle = time.time()
        try:
            rows = []
            for d15 in s15s:
                jf = d15 / "jobs.jsonl"
                rows += [json.loads(l) for l in jf.read_text().splitlines() if l.strip()] if jf.exists() else []
            merged = set(st["merged_jobs"]); added = 0
            for r in rows:
                xd = r.get("xml_dir")
                if not xd or xd in merged:
                    continue
                mp = Path(xd) / "_dedup_map.jsonl"
                for l in (mp.read_text().splitlines() if mp.exists() else []):
                    if not l.strip():
                        continue
                    d = json.loads(l)
                    if d["fp"] in st["seen"]:
                        continue
                    st["n"] += 1; name = f"inst-{st['n']:06d}"; st["seen"][d["fp"]] = name; st["order"].append(name)
                    for ext in (".txt", ".xml"):
                        src = Path(xd) / (d["name"][:-4] + ext)
                        if src.exists():
                            tmp = base / "xml" / f".tmp-{name}{ext}"; shutil.copyfile(src, tmp); os.replace(tmp, base / "xml" / f"{name}{ext}")
                    st["info"][name] = dict(core=r["core"], seed=r["seed"], merged_at=now())
                    smap.write(json.dumps({"name": name + ".xml", "core": r["core"], "seed": r["seed"], "job": xd,
                                           "source": d["name"], "fp": d["fp"], "time": now()}) + "\n")
                    added += 1
                st["merged_jobs"].append(xd); merged.add(xd)
            save()
            log(f"merge: +{added} (total {len(st['order'])}) from {len(rows)} finished jobs")
            def publish_all(ready, partial, done15):
                bs = max(a.max_batch, min(1500, len(ready) // 3)) if st["batch"] >= 2 else a.max_batch
                for k0 in range(0, len(ready), bs):
                    chunk = ready[k0:k0 + bs]
                    if len(chunk) < a.min_batch and not done15 and k0 > 0:
                        break
                    publish(chunk, partial)
            def publish(ready, partial):
                st["batch"] += 1; b = f"b{st['batch']:04d}"; bd = sd / "batches" / b
                if bd.exists():
                    shutil.rmtree(bd)
                srcd = bd / "src"; (srcd).mkdir(parents=True)
                os.symlink(base / "xml", srcd / "xml")
                for m in MODES:
                    for d in ("asm", "ann", "llvm"):
                        (srcd / m / d).mkdir(parents=True)
                    for s in ready:
                        if s in partial and m not in partial[s]:
                            continue
                        for d, ext in (("asm", ".s"), ("ann", ".ann.json"), ("llvm", ".ann.json")):
                            p = base / m / d / f"{s}{ext}"
                            if p.exists():
                                os.symlink(p, srcd / m / d / f"{s}{ext}")
                t3 = time.time()
                r3, r4 = vocab_rows(srcd, bd, ready), None
                ok = r3
                log(f"publish {b}: {len(ready)} stems ({len(partial)} partial) no post-passes (fanout_v2.vocab_rj), rows ok={ok}")
                P = list(ready)
                if ok:
                    keep = set(P)
                    out = bd / "out"
                    for m in MODES:
                        for d in ("asm", "ann"):
                            (out / m / d).mkdir(parents=True, exist_ok=True)
                            for p in (bd / "jmp" / m / d).iterdir():
                                if p.name.split(".")[0] in keep:
                                    shutil.copy2(p, out / m / d / p.name)
                            for p in (bd / "jmp" / m / d).iterdir():
                                if d == "ann" or p.name.split(".")[0] not in keep:
                                    continue
                                acopy(p, final / m / d / p.name)
                        for p in (bd / "jmp" / m / "ann").iterdir():
                            if p.name.split(".")[0] in keep:
                                acopy(p, final / m / "ann" / p.name)
                    (out / "xml").mkdir(exist_ok=True)
                    for s in P:
                        for ext in (".xml", ".txt"):
                            p = base / "xml" / f"{s}{ext}"
                            if p.exists():
                                acopy(p, final / "xml" / p.name); shutil.copy2(p, out / "xml" / p.name)
                    for t, dst in (("rmw/rmw_stems.tsv", "rmw_stems.tsv"), ("jmp_rows/jmp_stems.tsv", "jmp_stems.tsv")):
                        p = bd / t
                        if p.exists():
                            lines = p.read_text().splitlines()
                            agg = final / dst
                            old = agg.read_text()
                            if not old and lines:
                                old = lines[0] + "\n"
                            body = [l for l in lines[1:] if set(l.split("\t")) & keep]
                            tmp = agg.parent / f".{agg.name}.tmp"; tmp.write_text(old + "".join(l + "\n" for l in body)); os.replace(tmp, agg)
                    tpub = now()
                    rows_m = "".join(f"{s}\t{st['info'].get(s, {}).get('core')}\t{st['info'].get(s, {}).get('seed')}\t{st['info'].get(s, {}).get('merged_at')}"
                                     f"\t{tpub}\t{b}\t{','.join(partial.get(s, MODES))}\n" for s in P)
                    tmp = man.parent / ".MANIFEST.tsv.tmp"; tmp.write_text(man.read_text() + rows_m); os.replace(tmp, man)
                    (out / "MANIFEST_batch.tsv").write_text(man.read_text().splitlines()[0] + "\n" + rows_m)
                    for t, nm in (("rmw/rmw_stems.tsv", "rmw_batch.tsv"), ("jmp_rows/jmp_stems.tsv", "jmp_batch.tsv")):
                        p = bd / t
                        ls_ = p.read_text().splitlines() if p.exists() else []
                        (out / nm).write_text("".join(l + "\n" for l in ls_[:1] + [l for l in ls_[1:] if set(l.split("\t")) & keep]))
                    with open(out / "SHA256SUMS", "w") as f:
                        for p in sorted(out.rglob("*")):
                            if p.is_file() and p.name != "SHA256SUMS":
                                f.write(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out)}\n")
                    st["published"] += ready
                    (bd / "PUBLISHED").write_text(f"{tpub} {len(ready)} stems\n")
                    write_prov(final, st, s15s, base, cfg, code, a)
                    log(f"published {b}: total published {len(st['published'])} cpu_s={st.get('cpu_s')}")
                save()
            pub = set(st['published'])
            pending = [x for x in st['order'] if x not in pub]
            ready, partial = [], {}
            for s in pending:
                have = [m for m in MODES if (base / m / "ann" / f"{s}.ann.json").exists() and (base / m / "asm" / f"{s}.s").exists()]
                if len(have) == len(MODES):
                    ready.append(s)
                else:
                    st["tries"][s] = st["tries"].get(s, 0) + 1
                    if st["tries"][s] >= 4:
                        ready.append(s); partial[s] = have
            done15 = all((d15 / "SUMMARY.json").exists() for d15 in s15s)
            if ready and (len(ready) >= a.min_batch or done15):
                publish_all(ready, partial, done15)
            pub = set(st['published'])
            pending = [x for x in st['order'] if x not in pub]
            if pending:
                t2 = time.time()
                r2 = run_cpu(st, "stage2", [sys.executable, "STAGE1_alloy/gen/stage2_sharded.py", "--config", str(cfg),
                                     "--model", a.base_name, "--jobs", str(a.jobs)], cwd=str(code))
                log(f"stage2: rc={r2.returncode} secs={round(time.time()-t2)}" + (f"\n{r2.stderr[-3000:]}" if r2.returncode else ""))
            if done15 and len(st["order"]) == len(st["published"]) and all(r.get("xml_dir") in set(st["merged_jobs"]) for r in rows if r.get("xml_dir")):
                n_nt = len(list((final / MODES[0] / "asm").glob("*.s"))); n_t = len(list((final / MODES[1] / "asm").glob("*.s"))) if len(MODES) > 1 else 0
                summs = [json.loads((d15 / "SUMMARY.json").read_text()) for d15 in s15s]
                summ = dict(distinct_global=sum(x.get("distinct_global", 0) for x in summs), jobs=sum(x.get("jobs", 0) for x in summs),
                            exhausted_cores=",".join(str(x.get("exhausted_cores")) for x in summs), cores=",".join(str(x.get("cores")) for x in summs))
                (final / "READY").write_text(
                    f"READY {now()}: {a.final_name} = {a.family_label} core-pinned loose-pin lpP corpus, streamed.\n"
                    f"Stage 1: {a.family_label}_core_ri RI cores, {s15}/cores.json; Stage 1.5: stage15lp.py {s15} "
                    f"(distinct {summ.get('distinct_global')}, jobs {summ.get('jobs')}, exhausted cores {summ.get('exhausted_cores')}/{summ.get('cores')}); "
                    f"merged into {base}/xml ({len(st['order'])} programs, _stream_map.jsonl).\n"
                    + f"Stage 2: {cfg.name} (fanout_v2.vocab_rj: RMW and jmp drawn uniformly in Stage 2); {st['batch']} batches.\n"
                    + f"tests not_taken {n_nt}, taken {n_t}; MANIFEST.tsv, rmw_stems.tsv, jmp_stems.tsv; code {code} (SHA256SUMS).\n")
                write_prov(final, st, s15s, base, cfg, code, a, ready=True)
                log(f"READY written: programs {len(st['order'])}, tests {n_nt} + {n_t}")
                break
        except Exception:
            log(f"EXCEPTION\n{traceback.format_exc()}")
        time.sleep(max(5, a.interval - (time.time() - t_cycle)))
    log("END")


if __name__ == "__main__":
    main()
