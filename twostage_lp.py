import argparse, datetime as dt, json, re, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LP = ROOT / "STAGE1_alloy/gen"
PT = ROOT / "STAGE1_alloy/gen"


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def load(p):
    t = Path(p).read_text()
    return json.loads(re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", t, flags=re.S)))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--config", required=True); ap.add_argument("--ws", required=True)
    ap.add_argument("--alloy-only", action="store_true", help="run Stage 1 / 1.5 (Alloy) only; no Stage-2 stream "
                    "(start stream_fp.py later on <ws>/runs15/<lp_model>; it resumes from the finished jobs)")
    a = ap.parse_args()
    global ALLOY_ONLY
    ALLOY_ONLY = a.alloy_only
    cfg = load(a.config); T = cfg["twostage_lp"]; ws = Path(a.ws).resolve()
    for d in ("logs", "stage1/parts", "stage1/logs", "runs15", "cfg"):
        (ws / d).mkdir(parents=True, exist_ok=True)
    logf = open(ws / "logs" / "twostage_lp.log", "a", buffering=1)
    def log(m):
        logf.write(f"{now()} {m}\n"); print(m, flush=True)
    models = ROOT / "STAGE1_alloy/models"
    core, lp = models / f"{T['core_model']}.als", models / f"{T['lp_model']}.als"
    log(f"START config={a.config} ws={ws} core={core} lp={lp} corpus={T['corpus']}")
    s1 = T.get("stage1", {}); fam = T["core_model"]
    if s1.get("reuse_cores"):
        import hashlib
        body = core.read_text()
        sh = hashlib.sha256(body.encode()).hexdigest()
        if sh != s1["reuse_sha256"]:
            sys.exit(f"twostage_lp: reuse_cores were made by core model {s1['reuse_sha256'][:16]}, installed {core.name} is {sh[:16]}")
        cores = s1["reuse_cores"]
        log(f"stage1 REUSED: {cores} (core model sha256 {sh[:16]} matches)")
        return run15(cfg, T, ws, lp, cores, log)
    return stage1_and_rest(cfg, T, ws, core, lp, s1, fam, log)


def stage1_and_rest(cfg, T, ws, core, lp, s1, fam, log):
    if not (ws / "stage1/parts" / fam / "partitions.json").exists():
        subprocess.run([sys.executable, str(PT / "partition_stage1.py"), str(core), str(ws / "stage1/parts" / fam)], check=True)
    link = ws / "stage1/STAGE1_alloy"
    if not link.exists():
        link.symlink_to(ROOT / "STAGE1_alloy")
    st1 = subprocess.Popen([sys.executable, "-u", str(PT / "launch_stage1.py"), "--ws", str(ws / "stage1"), "--families", fam,
                            "--jobs", str(s1.get("jobs", 8)), "--cap", str(s1.get("cap", 200000)),
                            "--timeout", str(s1.get("timeout_s", 10800)), "--xmx", s1.get("xmx", "8g")],
                           stdout=open(ws / "logs/launch_stage1.out", "a"), stderr=subprocess.STDOUT)
    log(f"stage1 launched pid={st1.pid}")
    parts = json.loads((ws / "stage1/parts" / fam / "partitions.json").read_text())["partitions"]
    wait = [p["name"] for p in parts if p["k"] < s1.get("wait_k", 6)]
    def ended(name):
        lg = ws / "stage1/logs" / f"{fam}__{name}.log"
        return lg.exists() and "VERDICT=" in lg.read_text(errors="replace")
    while not all(ended(n) for n in wait):
        if st1.poll() is not None and not all(ended(n) for n in wait):
            log("stage1 launcher exited before the waited partitions ended"); break
        time.sleep(30)
    cores = [str(ws / "stage1/out" / fam / p["name"] / "stage1_xml") for p in parts
             if p["name"] in wait and (ws / "stage1/out" / fam / p["name"] / "stage1_xml").exists()]
    log(f"stage1 partitions below k={s1.get('wait_k', 6)} ended; Stage 1.5 starts on {cores} (larger partitions keep running; "
        "their cores are not used by this run)")
    return run15(cfg, T, ws, lp, cores, log)


ALLOY_ONLY = False


def run15(cfg, T, ws, lp, cores, log):
    fam = T["core_model"]
    s15 = T.get("stage15", {}); out15 = ws / "runs15" / T["lp_model"]
    p15 = subprocess.Popen([sys.executable, "-u", str(LP / "stage15lp.py"), "--base", str(lp), "--cores", *cores, "--out", str(out15),
                            "--code", str(ROOT), "--slots", str(s15.get("slots", 40)), "--job-timeout", str(s15.get("job_timeout", 300)),
                            "--budget-s", str(s15.get("budget_s", 5400)), "--cap", str(s15.get("cap", 25)),
                            "--walk-p", str(s15.get("walk_p", 0.05)), "--xmx", s15.get("xmx", "4g"),
                            "--spread", str(s15.get("spread", 2)), "--dedup-level", s15.get("dedup_level", "seed")]
                           + (["--shuffle-seed", str(s15["shuffle_seed"])] if "shuffle_seed" in s15 else [])
                           + (["--target-distinct", str(s15["target_distinct"])] if s15.get("target_distinct") else []),
                           stdout=open(ws / "logs/stage15lp.out", "a"), stderr=subprocess.STDOUT)
    log(f"stage15lp launched pid={p15.pid} out={out15}")
    if ALLOY_ONLY:
        log(f"--alloy-only: no Stage-2 stream; Stage 1.5 output {out15}")
        rc15 = p15.wait(); log(f"stage15lp ended rc={rc15}")
        log("END (alloy-only)")
        return
    src = ROOT / T["stage2_config"]; txt = src.read_text(); sm = T.get("stream", {})
    txt2 = re.sub(r'"testset_dir"\s*:\s*"[^"]*"', f'"testset_dir": "{cfg["paths"]["testset_dir"]}"', txt, count=1)
    txt2 = re.sub(r'"jobs"\s*:\s*\d+', f'"jobs": {sm.get("jobs", 24)}', txt2, count=1)
    scfg = ws / "cfg" / f"{src.stem}_stream.jsonc"
    scfg.write_text(txt2)
    ps = subprocess.Popen([sys.executable, "-u", str(LP / "stream_fp.py"), "--s15", str(out15), "--base-name", T["corpus"] + "_base",
                           "--final-name", T["corpus"], "--cfg", str(scfg), "--code", str(ROOT), "--ts-dir", cfg["paths"]["testset_dir"],
                           "--ws", str(ws), "--stage1-logs", f"stage1/logs/{fam}__*.log", "--family-label", T["family"],
                           "--interval", str(sm.get("interval", 120)), "--jobs", str(sm.get("jobs", 24)),
                           "--min-batch", str(sm.get("min_batch", 50)), "--max-batch", str(sm.get("max_batch", 150))]
,
                          stdout=open(ws / "logs/stream_fp.out", "a"), stderr=subprocess.STDOUT)
    log(f"stream_fp launched pid={ps.pid}")
    rc15 = p15.wait(); log(f"stage15lp ended rc={rc15}")
    rcs = ps.wait(); log(f"stream_fp ended rc={rcs} (READY: {(Path(cfg['paths']['testset_dir']) / T['corpus'] / 'READY').exists()})")
    log("END (Stage-1 partitions at or above wait_k may still be running under launch_stage1.py)")


if __name__ == "__main__":
    main()
