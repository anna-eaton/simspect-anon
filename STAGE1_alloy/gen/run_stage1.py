import argparse
import datetime as dt
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE1 = HERE.parent
JAVA = os.environ.get("SIMSPECT_JAVA") or shutil.which("java") or "java"
DISK = os.environ.get("SIMSPECT_DISK") or str(STAGE1)


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def free_gb():
    return shutil.disk_usage(DISK).free / 1e9


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--cap", type=int, default=100000,
                    help="instance cap (= alloy.max_instances in runconfigs/*.jsonc)")
    ap.add_argument("--timeout", type=int, default=6 * 3600, help="wall-clock seconds")
    ap.add_argument("--poll", type=int, default=60)
    ap.add_argument("--xmx", default="4g", help="JVM max heap (3 runs in parallel on an 18 GB Mac)")
    ap.add_argument("--min-free-start", type=float, default=50.0)
    ap.add_argument("--min-free-run", type=float, default=40.0)
    a = ap.parse_args()

    model = Path(a.model).resolve()
    out = Path(a.out).resolve()
    logp = Path(os.path.expanduser(a.log))
    logp.parent.mkdir(parents=True, exist_ok=True)
    log = open(logp, "a", buffering=1)

    def L(msg):
        log.write(f"{now()} [{a.name}] {msg}\n")

    L("=" * 70)
    L(f"START pid={os.getpid()} host={os.uname().nodename}")
    try:
        raw = model.read_bytes()
        L(f"model={model}")
        L(f"model_sha256={hashlib.sha256(raw).hexdigest()}")
        scope = [l for l in raw.decode().splitlines() if l.startswith("} for ")]
        L(f"scope_line={scope[0] if scope else '??'}")
        L(f"out_dir={out} cap={a.cap} timeout_s={a.timeout} xmx={a.xmx} poll_s={a.poll}")
        fg = free_gb()
        L(f"disk_free_GB={fg:.1f} (start needs >= {a.min_free_start}, stop if < {a.min_free_run})")
        if fg < a.min_free_start:
            L("VERDICT=NOT_STARTED reason=disk_free_below_start_threshold")
            return 2
        if out.exists() and any(out.glob("inst-*.xml")):
            L(f"VERDICT=NOT_STARTED reason=output_dir_not_empty ({out}); delete it to rerun")
            return 3
        out.mkdir(parents=True, exist_ok=True)
        cmd = [JAVA, f"-Xmx{a.xmx}", "-cp", "alloy6.jar:.", "a6CountModels",
               str(model), str(out), str(a.cap)]
        L(f"cwd={STAGE1}")
        L(f"cmd={' '.join(cmd)}")
        so = open(out / "_java_stdout.txt", "w")
        se = open(out / "_java_stderr.txt", "w")
        t0 = time.time()
        p = subprocess.Popen(cmd, cwd=STAGE1, stdout=so, stderr=se)
        L(f"java_pid={p.pid}")
        verdict = None
        last_n = -1
        while True:
            try:
                rc = p.wait(timeout=a.poll)
                break
            except subprocess.TimeoutExpired:
                pass
            n = sum(1 for _ in out.glob("inst-*.xml"))
            fg = free_gb()
            el = int(time.time() - t0)
            if n != last_n or el % (10 * a.poll) < a.poll:
                L(f"progress elapsed_s={el} instances={n} disk_free_GB={fg:.1f}")
                last_n = n
            if fg < a.min_free_run:
                verdict = "DISK_GUARD"
                L(f"disk free {fg:.1f} GB < {a.min_free_run} GB: killing java")
                p.kill(); rc = p.wait(); break
            if el >= a.timeout:
                verdict = "TIMEOUT"
                L(f"timeout {a.timeout}s reached: killing java (instances so far are kept)")
                p.kill(); rc = p.wait(); break
        so.close(); se.close()
        n = sum(1 for _ in out.glob("inst-*.xml"))
        stdout = (out / "_java_stdout.txt").read_text(errors="replace")
        stderr = (out / "_java_stderr.txt").read_text(errors="replace")
        if verdict is None:
            if rc != 0:
                verdict = "ERROR"
            elif "Total models:" in stdout and n < a.cap:
                verdict = "EXHAUSTED"
            elif n >= a.cap:
                verdict = "CAPPED"
            else:
                verdict = "UNKNOWN"
        L(f"java_rc={rc} instances={n} elapsed_s={int(time.time() - t0)}")
        L(f"java_stdout: {stdout.strip()[-2000:]}")
        if stderr.strip():
            L("java_stderr (full):\n" + stderr)
        L(f"VERDICT={verdict}")
        return 0 if verdict in ("EXHAUSTED", "CAPPED") else 1
    except Exception:
        import traceback
        L("EXCEPTION:\n" + traceback.format_exc())
        L("VERDICT=ERROR")
        return 1
    finally:
        L(f"END pid={os.getpid()}")
        log.close()


if __name__ == "__main__":
    sys.exit(main())
