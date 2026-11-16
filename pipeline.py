
from __future__ import annotations

import argparse
import json
import time
import zlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from simspect_paths import ROOT, resolve


def load_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*',  '', text)
    return json.loads(text)


def phase_asm(cfg: dict, model: str, out_base: Path, force: bool) -> None:
    llvm_dir = out_base / "llvm"
    asm_dir  = out_base / "asm"
    ann_dir  = out_base / "ann"

    ll_files = sorted(llvm_dir.glob("*.ll")) if llvm_dir.exists() else []
    if not ll_files:
        sys.exit("error: generated/<model>/llvm/ is empty — run the 'llvm' phase first")

    asm_dir.mkdir(parents=True, exist_ok=True)
    ann_dir.mkdir(parents=True, exist_ok=True)

    stage2 = resolve(cfg["paths"]["stage2_dir"])

    if force:
        todo = ll_files
    else:
        todo = [f for f in ll_files if not (asm_dir / (f.stem + ".s")).exists()]

    if not todo:
        done = sum(1 for f in ll_files if (asm_dir / (f.stem + ".s")).exists())
        print(f"[asm] All {done} .s files already compiled — skipping")
        return

    jobs = max(1, int(cfg.get("gem5", {}).get("jobs", 8)))
    print(f"[asm] Compiling {len(todo)}/{len(ll_files)} .ll files  (jobs={jobs}) …")
    ok = err = 0

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _one(ll_path_str: str) -> tuple[str, int, str]:
        r = subprocess.run(
            [
                sys.executable,
                str(stage2 / "compile_annotate.py"),
                ll_path_str,
                "--out-dir", str(asm_dir),
                "--ann-dir", str(ann_dir),
            ],
            capture_output=True, text=True,
        )
        return (ll_path_str, r.returncode, r.stderr.strip()[:200])

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futures = [ex.submit(_one, str(ll)) for ll in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                ll_path_str, rc, stderr_snippet = fut.result()
            except Exception as e:
                err += 1
                print(f"  [exc] worker raised: {e}")
                continue
            if rc == 0:
                ok += 1
            else:
                err += 1
                if err <= 20:
                    print(f"  [err] {Path(ll_path_str).name}: {stderr_snippet}")
                elif err == 21:
                    print(f"  [err] (suppressing further per-file errors)")
            if i % 500 == 0:
                print(f"  progress: {i}/{len(todo)}  ok={ok}  errors={err}")

    msg = f"[asm] Done — {ok} compiled"
    if err:
        msg += f", {err} errors"
    print(msg)


_KIND_TO_CHECKER = {
    "ld":      "check_ld.py",
    "br_x":    "check_br.py",
    "other_x": "check_other.py",
}
_DEFAULT_CHECKER = "check_ld.py"


def _checker_for(gem5_cfg: dict, kind: str) -> str:
    override = (gem5_cfg or {}).get("checker")
    if override:
        return str(override)
    return _KIND_TO_CHECKER.get(kind, _DEFAULT_CHECKER)

def _read_xmit_kind(ann_dir: Path, stem: str) -> str:
    ann_path = ann_dir / (stem + ".ann.json")
    ann = json.loads(ann_path.read_text())
    kind = ann.get("xmit", {}).get("kind")
    if not kind:
        raise ValueError(f"{ann_path}: missing xmit.kind")
    return kind


import itertools
import random as _random


def _classify_branches(ann: dict) -> tuple[list, list]:
    xmit_pc = ann.get("xmit", {}).get("pc")
    resolved, unresolved = [], []
    for entry in ann.get("annotations", []):
        pc = entry.get("branch_pc")
        if pc is None or pc == xmit_pc:
            continue
        mode = entry.get("mode", "")
        if mode == "correctly_not_taken":
            resolved.append(pc)
        elif mode in ("mispredict_not_taken", "mispredict_taken"):
            unresolved.append(pc)
    return resolved, unresolved


def _grid_points(resolved_pcs: list, points: list,
                 unresolved_points: list = None, max_grid: int = None,
                 seed: int = 0) -> list:
    if not resolved_pcs:
        base = [{}]
    else:
        base = [dict(zip(resolved_pcs, combo))
                for combo in itertools.product(points, repeat=len(resolved_pcs))]
    if unresolved_points:
        grid = []
        for d in base:
            for u in unresolved_points:
                e = dict(d)
                e["__unresolved__"] = int(u)
                grid.append(e)
    else:
        grid = base
    if max_grid is not None and len(grid) > max_grid:
        grid = _random.Random(seed).sample(grid, max_grid)
    return grid


def _timing_grid_point(stem: str, sweep_cfg: dict):
    g = sweep_cfg.get("timing_grid")
    if not g:
        return None
    import hashlib
    pts = [(int(u), int(r)) for u in g.get("unresolved", []) for r in g.get("resolved", [])]
    if not pts:
        raise ValueError("sweep.timing_grid needs non-empty unresolved and resolved lists")
    k = int(hashlib.sha256(f"{g.get('seed', 'tgrid-v1')}:{stem}".encode()).hexdigest()[:8], 16) % len(pts)
    return pts[k]


def _per_branch_all(grid, resolved, unresolved, sweep_cfg, stem):
    tp = _timing_grid_point(stem, sweep_cfg)
    if tp is None:
        raise ValueError("sweep.timing_grid is required")
    u, r = tp
    out = []
    for g in grid:
        e = dict(g); e.update({pc: u for pc in unresolved}); e.update({pc: r for pc in resolved}); out.append(e)
    return out


def _inject_stalls(ann: dict, stalls: dict, unresolved_stall: int) -> dict:
    out = json.loads(json.dumps(ann))
    xmit_pc = out.get("xmit", {}).get("pc")
    for entry in out.get("annotations", []):
        pc = entry.get("branch_pc")
        if pc is None:
            continue
        if pc == xmit_pc:
            entry["resolve_stall_cycles"] = 0
            continue
        mode = entry.get("mode", "")
        if mode == "correctly_not_taken":
            entry["resolve_stall_cycles"] = int(stalls.get(pc, 0))
        elif mode in ("mispredict_not_taken", "mispredict_taken"):
            entry["resolve_stall_cycles"] = int(stalls[pc]) if pc in stalls else int(
                stalls.get("__unresolved__", unresolved_stall))
    return out


def _enumerate_grid_for_corpus(s_files: list, ann_dir: Path,
                               sweep_cfg: dict) -> tuple[list, dict, int]:
    points = sweep_cfg.get("points", [0])

    manifest: dict = {}
    per_grid_idx: dict = {}

    for sf in s_files:
        ann_path = ann_dir / (sf.stem + ".ann.json")
        if not ann_path.exists():
            continue
        ann = json.loads(ann_path.read_text())
        resolved, unresolved = _classify_branches(ann)
        grid = _grid_points(
            resolved, points,
            unresolved_points=sweep_cfg.get("unresolved_points"),
            max_grid=sweep_cfg.get("max_grid"),
            seed=zlib.crc32(sf.stem.encode()))
        grid = _per_branch_all(grid, resolved, unresolved, sweep_cfg, sf.stem)
        manifest[sf.stem] = grid

        for idx, stalls in enumerate(grid):
            per_grid_idx.setdefault(idx, []).append((sf, ann_path, stalls))

    if not per_grid_idx:
        return [], manifest, 0

    max_grid_size = max(per_grid_idx.keys()) + 1
    return per_grid_idx, manifest, max_grid_size


def _materialise_grid_run(grid_entries: list, variant_dir: Path,
                          unresolved_stall: int) -> list:
    variant_dir.mkdir(parents=True, exist_ok=True)
    s_paths: list = []

    for sf, ann_path, stalls in grid_entries:
        v_s = variant_dir / sf.name
        if v_s.exists() or v_s.is_symlink():
            v_s.unlink()
        v_s.symlink_to(sf.resolve())

        v_ann = variant_dir / (sf.stem + ".ann.json")
        ann = json.loads(ann_path.read_text())
        v_ann.write_text(json.dumps(
            _inject_stalls(ann, stalls, unresolved_stall), indent=2))

        s_paths.append(v_s)

    return s_paths


def _aggregate_sweep_results(per_grid_results: dict, manifest: dict,
                              sweep_dir: Path) -> list:
    aggregated: list = []

    for base_stem, grid in manifest.items():
        per_grid_summary = []
        any_hit = False
        any_err = False
        n_invalid = 0
        triggered = []
        cs_keys: dict = {}

        for idx, stalls in enumerate(grid):
            batch_results = per_grid_results.get(idx, [])
            row = next((r for r in batch_results
                        if r.get("name") == base_stem), None)
            if row is None:
                per_grid_summary.append({"stalls": stalls, "result": None})
                any_err = True
                continue
            hit = bool(row.get("issued_in_window"))
            status = row.get("status", "unknown")
            if row.get("cache_setup_mode") or row.get("cache_setup", "warm") != "warm":
                for k in ("cache_setup", "cache_setup_mode", "cache_setup_seed",
                          "cache_setup_choices"):
                    if k in row:
                        cs_keys.setdefault(k, row[k])
            per_grid_summary.append({
                "stalls":           stalls,
                "issued_in_window": hit,
                "status":           status,
            })
            if hit:
                any_hit = True
                triggered.append(stalls)
            if status == "invalid":
                n_invalid += 1
            elif status not in ("ok", None):
                any_err = True

        sidecar = sweep_dir / (base_stem + "_sweep.json")
        sidecar.write_text(json.dumps({
            "stem":             base_stem,
            "grid_points":      per_grid_summary,
            "triggered_points": triggered,
        }, indent=2))

        aggregated.append({
            "name":             base_stem,
            "issued_in_window": any_hit,
            "status":           "ok" if not any_err else "error",
            "sweep_grid_size":  len(grid),
            "sweep_triggered":  len(triggered),
            "sweep_invalid":    n_invalid,
            **cs_keys,
        })

    return aggregated


def _build_gem5_env(gem5_cfg: dict, spec_cfg: dict) -> dict:
    env = os.environ.copy()

    binary = gem5_cfg.get("binary")
    cfg_script = gem5_cfg.get("config_script")
    cpu = gem5_cfg.get("cpu_type")
    dbg_flags = gem5_cfg.get("debug_flags")
    dbg_file = gem5_cfg.get("debug_file")

    if binary:
        env["SIMSPECT_GEM5_BIN"] = str(binary)
        bpath = Path(binary)
        if "build" in bpath.parts:
            idx = bpath.parts.index("build")
            env["SIMSPECT_GEM5_DIR"] = str(Path(*bpath.parts[:idx]))
    if cfg_script:
        env["SIMSPECT_SE_CONFIG"] = str(cfg_script)
    if cpu:
        env["SIMSPECT_GEM5_CPU"] = str(cpu)
    if isinstance(dbg_flags, list) and dbg_flags:
        env["SIMSPECT_GEM5_DBG_FLAG"] = ",".join(str(f) for f in dbg_flags)
    if dbg_file:
        env["SIMSPECT_GEM5_DBG_FILE"] = str(dbg_file)

    if gem5_cfg.get("branch_ann_enable"):
        env["SIMSPECT_BRANCH_ANN_ENABLE"] = "1"


    if gem5_cfg.get("allow_leaked"):
        env["SIMSPECT_ALLOW_LEAKED"] = "1"

    fnc_stall = gem5_cfg.get("fnc_commit_stall_cycles", 0)
    if fnc_stall:
        env["SIMSPECT_FNC_COMMIT_STALL_CYCLES"] = str(int(fnc_stall))

    cache_setup = str(gem5_cfg.get("cache_setup", "warm")).strip().lower()
    if cache_setup != "warm":
        env["SIMSPECT_CACHE_SETUP"] = cache_setup
    if gem5_cfg.get("cache_setup_fill_bytes") is not None:
        env["SIMSPECT_CACHE_SETUP_FILL_BYTES"] = str(gem5_cfg["cache_setup_fill_bytes"])

    extra = gem5_cfg.get("extra_args")
    if isinstance(extra, list) and extra:
        env["SIMSPECT_GEM5_EXTRA"] = "\x1f".join(str(a) for a in extra)

    crit = gem5_cfg.get("criterion")
    if crit:
        cpath = Path(crit)
        if not cpath.is_absolute():
            cpath = Path(__file__).resolve().parent / cpath
        if not cpath.exists():
            sys.exit(f"error: gem5.criterion {crit} not found ({cpath})")
        env["SIMSPECT_CRITERION"] = str(cpath)
    if gem5_cfg.get("checker") == "check_footprint.py" and not crit:
        sys.exit("error: gem5.checker=check_footprint.py needs gem5.criterion "
                 "(specs/leakage/<defense>.json)")

    fast = gem5_cfg.get("fast_path", True)
    if not isinstance(fast, bool):
        sys.exit(f"error: gem5.fast_path must be true or false, got {fast!r}")
    if fast:
        env["SIMSPECT_FAST_PATH"] = "1"
    else:
        env.pop("SIMSPECT_FAST_PATH", None)

    return env


def _run_checker_batch(checker: Path, s_files: list, ann_dir: Path,
                       batch_out: Path, scheme: int, jobs: int,
                       keep_tmp: bool,
                       env: Optional[dict] = None) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix="simspect_gem5_") as tmp:
        tmp_path = Path(tmp)
        for sf in s_files:
            shutil.copy(sf, tmp_path / sf.name)
            ann_src = ann_dir / (sf.stem + ".ann.json")
            if ann_src.exists():
                shutil.copy(ann_src, tmp_path / ann_src.name)

        cmd = [
            sys.executable, str(checker),
            str(tmp_path),
            "--jobs",   str(jobs),
            "--out",    str(batch_out),
            "--scheme", str(scheme),
        ]
        if keep_tmp:
            cmd.append("--keep-tmp")

        if env is not None and env.get("SIMSPECT_FAST_PATH") == "1" and not env.get("SIMSPECT_FAST_PATH_LOG"):
            env = dict(env, SIMSPECT_FAST_PATH_LOG=str(Path(batch_out).parent / "fastpath.log"))

        return subprocess.run(cmd, check=False, capture_output=True, text=True,
                              env=env)


def _collect_batch_results(batch_out: Path, existing: list,
                           already_done: set, hits_f: Path,
                           batch_label: str) -> int:
    if not batch_out.exists():
        print(f"  [warn] {batch_label} produced no output file")
        return 0

    batch_results = json.loads(batch_out.read_text())
    batch_hits = [r["name"] for r in batch_results
                  if r.get("issued_in_window") is True]
    batch_errs = sum(1 for r in batch_results if r.get("status") != "ok")

    for r in batch_results:
        if r.get("status") == "error":
            err_msg = (r.get("error") or "")[:160]
            print(f"    [err] {r['name']}: {err_msg}")

    if batch_hits:
        with hits_f.open("a") as fh:
            fh.write("\n".join(batch_hits) + "\n")

    existing.extend(batch_results)
    already_done.update(r["name"] for r in batch_results)

    if batch_errs:
        print(f"    hits={len(batch_hits)}  errors={batch_errs}")
    elif batch_hits:
        print(f"    hits={len(batch_hits)}")

    return len(batch_hits)


def _phase_gem5_sweep(cfg: dict, model: str, ts_mode: Path, rs_mode: Path,
                      force: bool, s_files: list, ann_dir: Path) -> None:
    sweep_cfg = cfg.get("sweep", {})

    sweep_dir   = rs_mode / "sweep"
    variant_dir = sweep_dir / "variants"
    raw_dir     = sweep_dir / "raw_results"
    sweep_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    rs_mode.mkdir(parents=True, exist_ok=True)

    results_f = rs_mode / "window-results.json"
    hits_f    = rs_mode / "window-hits.txt"

    if not force and results_f.exists():
        print(f"[gem5:sweep] {results_f.name} already exists — pass --force to "
              "re-run sweep")
        return

    stage3   = resolve(cfg["paths"]["stage3_dir"])
    gem5_cfg = cfg.get("gem5", {})
    spec_cfg = cfg.get("speculation", {})
    scheme   = gem5_cfg.get("scheme", 2)
    jobs     = gem5_cfg.get("jobs", 8)
    keep_tmp = cfg.get("pipeline", {}).get("keep_tmp", False)
    batch_sz = cfg.get("alloy", {}).get("batch_size", 1000)
    checker_env = _build_gem5_env(gem5_cfg, spec_cfg)

    per_grid_idx, manifest, max_grid = _enumerate_grid_for_corpus(
        s_files, ann_dir, sweep_cfg)
    (sweep_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    n_runs = sum(len(entries) for entries in per_grid_idx.values()) \
             if isinstance(per_grid_idx, dict) else 0
    print(f"[gem5:sweep] {len(manifest)} tests × variable grid (max {max_grid} "
          f"points) → {n_runs} variant runs  "
          f"(points={sweep_cfg.get('points')}, "
          f"unresolved_stall={sweep_cfg.get('unresolved_stall_cycles')})")

    unresolved_stall = int(sweep_cfg.get("unresolved_stall_cycles", 0))

    per_grid_results: dict = {}
    batch_n = 0
    for grid_idx in sorted(per_grid_idx.keys()):
        entries = per_grid_idx[grid_idx]
        grid_subdir = variant_dir / f"point_{grid_idx:04d}"
        run_files = _materialise_grid_run(entries, grid_subdir,
                                          unresolved_stall)

        groups: dict = {}
        for vf in run_files:
            kind = _read_xmit_kind(ann_dir, vf.stem)
            script = _checker_for(gem5_cfg, kind)
            groups.setdefault(script, []).append(vf)

        grid_raw: list = []
        for script, files in sorted(groups.items()):
            checker = stage3 / script
            for start in range(0, len(files), batch_sz):
                batch_n += 1
                batch = files[start : start + batch_sz]
                batch_out = raw_dir / f"{time.strftime('%Y%m%d%H%M%S')}_grid{grid_idx:04d}_batch{batch_n:04d}_{script}.json"

                print(f"  grid {grid_idx} ({script}): "
                      f"{batch[0].stem} … {batch[-1].stem}  ({len(batch)} tests)")

                result = _run_checker_batch(checker, batch, grid_subdir,
                                            batch_out, scheme, jobs, keep_tmp,
                                            env=checker_env)
                for line in result.stdout.splitlines():
                    if "ERROR" in line or "[err]" in line.lower():
                        print(f"    {line.strip()}")
                if result.stderr.strip():
                    for line in result.stderr.strip().splitlines():
                        print(f"    [stderr] {line}")

                if batch_out.exists():
                    grid_raw.extend(json.loads(batch_out.read_text()))

        per_grid_results[grid_idx] = grid_raw

    aggregated = _aggregate_sweep_results(per_grid_results, manifest, sweep_dir)
    results_f.write_text(json.dumps(aggregated, indent=2))

    hits = [r["name"] for r in aggregated if r.get("issued_in_window")]
    if hits:
        hits_f.write_text("\n".join(hits) + "\n")
    else:
        hits_f.write_text("")

    hits_dir = rs_mode / "hits"
    if hits:
        hits_dir.mkdir(parents=True, exist_ok=True)
        for stem in hits:
            src = ts_mode / "asm" / (stem + ".s")
            if src.exists():
                shutil.copy(src, hits_dir / src.name)
        print(f"             Hits copied    → {hits_dir}/  ({len(hits)} files)")

    errs = sum(1 for r in aggregated if r.get("status") != "ok")
    print(f"\n[gem5:sweep] Done — {len(hits)} hits / {len(aggregated)} tests "
          f"({errs} errors)  across {n_runs} variant runs")
    print(f"             Results  → {results_f}")
    print(f"             Sweep    → {sweep_dir}/<stem>_sweep.json")


def phase_gem5(cfg: dict, model: str, ts_mode: Path, rs_mode: Path,
               force: bool) -> None:
    asm_dir = ts_mode / "asm"
    ann_dir = ts_mode / "ann"

    s_files = sorted(asm_dir.glob("*.s")) if asm_dir.exists() else []
    if not s_files:
        sys.exit("error: testsets/<model>/asm/ is empty — run the 'asm' phase first")
    if not ann_dir.exists() or not any(ann_dir.glob("*.ann.json")):
        sys.exit("error: testsets/<model>/ann/ is empty — run the 'asm' phase first")

    if cfg.get("sweep", {}).get("enabled"):
        if not cfg.get("gem5", {}).get("branch_ann_enable"):
            sys.exit("error: sweep.enabled requires gem5.branch_ann_enable: true "
                     "(modded gem5 build)")
        return _phase_gem5_sweep(cfg, model, ts_mode, rs_mode,
                                 force, s_files, ann_dir)

    rs_mode.mkdir(parents=True, exist_ok=True)
    results_f = rs_mode / "window-results.json"
    hits_f    = rs_mode / "window-hits.txt"

    if force:
        existing: list = []
        already_done: set = set()
        results_f.write_text("[]")
        hits_f.write_text("")
    elif results_f.exists():
        try:
            existing = json.loads(results_f.read_text())
        except Exception:
            existing = []
        already_done = {r["name"] for r in existing}
    else:
        existing = []
        already_done = set()
        results_f.write_text("[]")
        hits_f.write_text("")

    stage3   = resolve(cfg["paths"]["stage3_dir"])
    gem5_cfg = cfg.get("gem5", {})
    spec_cfg = cfg.get("speculation", {})
    scheme   = gem5_cfg.get("scheme", 2)
    jobs     = gem5_cfg.get("jobs", 8)
    keep_tmp = cfg.get("pipeline", {}).get("keep_tmp", False)
    batch_sz = cfg.get("alloy", {}).get("batch_size", 1000)

    checker_env = _build_gem5_env(gem5_cfg, spec_cfg)

    to_test = [
        sf for sf in s_files
        if sf.stem not in already_done
        and (ann_dir / (sf.stem + ".ann.json")).exists()
    ]

    if not to_test:
        print(f"[gem5] All {len(already_done)} tests already in results — skipping")
        return

    groups: dict = {}
    for sf in to_test:
        kind = _read_xmit_kind(ann_dir, sf.stem)
        script = _checker_for(gem5_cfg, kind)
        groups.setdefault(script, []).append(sf)

    print(f"[gem5] {len(to_test)} tests, per-type dispatch "
          f"(scheme={scheme}, jobs={jobs}):")
    for script, files in sorted(groups.items()):
        kinds_in_group = set(_read_xmit_kind(ann_dir, f.stem) for f in files)
        print(f"  {script}: {len(files)} tests  (kinds: {', '.join(sorted(kinds_in_group))})")

    cum_hits = 0
    batch_n = 0

    for script, group_files in sorted(groups.items()):
        checker = stage3 / script
        group_batches = (len(group_files) + batch_sz - 1) // batch_sz
        print(f"\n[gem5:{script}] {len(group_files)} tests → {group_batches} batches")

        for start in range(0, len(group_files), batch_sz):
            batch_n += 1
            batch = group_files[start : start + batch_sz]
            batch_label = f"batch {batch_n} ({script})"
            batch_out = rs_mode / f"batch_{batch_n:04d}_results.json"

            print(f"  {batch_label}: {batch[0].stem} … {batch[-1].stem}")

            result = _run_checker_batch(checker, batch, ann_dir, batch_out,
                                        scheme, jobs, keep_tmp,
                                        env=checker_env)
            for line in result.stdout.splitlines():
                if "ERROR" in line or "[err]" in line.lower():
                    print(f"    {line.strip()}")
            if result.stderr.strip():
                for line in result.stderr.strip().splitlines():
                    print(f"    [stderr] {line}")

            cum_hits += _collect_batch_results(
                batch_out, existing, already_done, hits_f, batch_label)
            results_f.write_text(json.dumps(existing, indent=2))

    print(f"\n  cumulative hits={cum_hits}")

    total = len(existing)
    hits  = sum(1 for r in existing if r.get("issued_in_window") is True)
    errs  = sum(1 for r in existing if r.get("status") != "ok")

    hit_stems = [r["name"] for r in existing if r.get("issued_in_window") is True]
    if hit_stems:
        hits_dir = rs_mode / "hits"
        hits_dir.mkdir(parents=True, exist_ok=True)
        for stem in hit_stems:
            src = ts_mode / "asm" / (stem + ".s")
            if src.exists():
                shutil.copy(src, hits_dir / src.name)

    print(f"\n[gem5] Done — {hits} hits / {total} total  ({errs} errors)")
    print(f"       Results → {results_f}")
    print(f"       Hits    → {hits_f}")


def main() -> None:
    ap = argparse.ArgumentParser(description="SimSpect engine: asm (compile + annotate) and gem5 (run the checkers) phases.")
    ap.add_argument("phase", choices=["asm", "gem5"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--force", action="store_true", help="Re-run phase even if output already exists")
    args = ap.parse_args()
    config_path = ROOT / args.config
    if not config_path.exists():
        sys.exit(f"error: config file not found: {config_path}")
    cfg = load_config(config_path)
    paths_cfg = cfg["paths"]
    testset_base = resolve(paths_cfg["testset_dir"]) / args.model
    results_base = resolve(paths_cfg["results_dir"]) / paths_cfg.get("results_name", args.model)
    testset_base.mkdir(parents=True, exist_ok=True)
    for m in cfg["speculation"]["branch_modes"]:
        ts_mode = testset_base / m
        ts_mode.mkdir(parents=True, exist_ok=True)
        if args.phase == "asm":
            phase_asm(cfg, args.model, ts_mode, args.force)
        else:
            phase_gem5(cfg, args.model, ts_mode, results_base / m, args.force)


if __name__ == "__main__":
    main()
