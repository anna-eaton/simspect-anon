
from __future__ import annotations

import argparse
import hashlib
import ctypes
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


def sample_keep(stem: str, fraction: float) -> bool:
    if fraction >= 1.0:
        return True
    if fraction <= 0.0:
        return False
    h = int(hashlib.md5(stem.encode()).hexdigest()[:8], 16)
    return (h / 0xFFFFFFFF) < fraction


GEM5_DIR  = Path(os.environ.get("SIMSPECT_GEM5_DIR",  "gem5"))
GEM5_BIN  = Path(os.environ.get("SIMSPECT_GEM5_BIN",  str(GEM5_DIR / "build/X86/gem5.opt")))
SE_CONFIG = Path(os.environ.get("SIMSPECT_SE_CONFIG", str(GEM5_DIR / "configs/example/se.py")))
GEM5_CPU  = os.environ.get("SIMSPECT_GEM5_CPU",  "X86O3CPU")
GEM5_DBG_FLAG = os.environ.get("SIMSPECT_GEM5_DBG_FLAG", "O3PipeView,LSQUnit")
GEM5_DBG_FILE = os.environ.get("SIMSPECT_GEM5_DBG_FILE", "pipeview.txt")

BRANCH_ANN_ENABLE = os.environ.get("SIMSPECT_BRANCH_ANN_ENABLE", "").lower() in (
    "1", "true", "yes", "on")

ALLOW_LEAKED = os.environ.get("SIMSPECT_ALLOW_LEAKED", "").lower() in (
    "1", "true", "yes", "on")


FNC_COMMIT_STALL_CYCLES: int = int(os.environ.get("SIMSPECT_FNC_COMMIT_STALL_CYCLES", "0"))
CACHE_SETUP: str = (os.environ.get("SIMSPECT_CACHE_SETUP") or "warm").strip().lower()
if CACHE_SETUP != "warm":
    if str(Path(__file__).resolve().parent) not in sys.path:
        sys.path.append(str(Path(__file__).resolve().parent))
    import cache_setup as _cs_mod
    if CACHE_SETUP not in _cs_mod.KNOWN:
        raise SystemExit(f"SIMSPECT_CACHE_SETUP={CACHE_SETUP!r} unknown "
                         f"(known: {', '.join(_cs_mod.KNOWN)})")
    try:
        _cs_mod.check_build(CACHE_SETUP, str(GEM5_BIN))
    except _cs_mod.CacheSetupError as _e:
        raise SystemExit(str(_e))

GEM5_TIMEOUT_S: int = int(os.environ.get("SIMSPECT_GEM5_TIMEOUT_S", "120"))
GEM5_MAX_TICK:  int = int(os.environ.get("SIMSPECT_GEM5_MAX_TICK", "100000000000"))

_scheme: int = 2


def _entry_asm(func_name: str) -> str:
    return textwrap.dedent(f"""\
        .global _start
        .section .text
        _start:
            call "{func_name}"
            mov $60, %rax
            xor %rdi, %rdi
            syscall
    """)


def build_binary(s_path: Path, workdir: Path, cache_setup_ok: bool = False) -> Path:
    if CACHE_SETUP != "warm" and not cache_setup_ok:
        raise RuntimeError(f"SIMSPECT_CACHE_SETUP={CACHE_SETUP} is applied only by "
                           "gem5_common.process_one; this caller builds directly")
    func_name = s_path.stem
    binary    = workdir / func_name
    patched_s = workdir / (func_name + "_patched.s")
    text = s_path.read_text()
    text = re.sub(r'^\s*\.addrsig\s*$', '', text, flags=re.MULTILINE)
    patched_s.write_text(text)
    entry_s = workdir / "_entry.s"
    entry_s.write_text(_entry_asm(func_name))
    func_o  = workdir / "func.o"
    entry_o = workdir / "entry.o"
    subprocess.run(["as", "-o", str(func_o),  str(patched_s)], check=True, capture_output=True)
    subprocess.run(["as", "-o", str(entry_o), str(entry_s)],   check=True, capture_output=True)
    subprocess.run(["ld", "-static", "-o", str(binary), str(entry_o), str(func_o)],
                   check=True, capture_output=True)
    return binary


def _func_base_addr(binary: Path, func_name: str) -> Optional[int]:
    try:
        out = subprocess.check_output(["objdump", "-d", str(binary)],
                                      text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return None
    m = re.search(r'^([0-9a-f]+) <' + re.escape(func_name) + r'>:',
                  out, re.MULTILINE)
    return int(m.group(1), 16) if m else None


def resolve_pc(binary: Path, func_name: str, ann_entry: dict) -> Optional[int]:
    addr = ann_entry.get("addr")
    if addr is not None:
        return int(addr)
    offset = ann_entry.get("x86_offset")
    if offset is None:
        return None
    base = _func_base_addr(binary, func_name)
    return (base + offset) if base is not None else None


_FORCE_MARKER = b"BR:predict_force"
_force_support: Dict[str, bool] = {}


def binary_has_resolve_hooks(gem5_bin: Path) -> bool:
    key = str(gem5_bin)
    if key not in _force_support:
        try:
            with open(gem5_bin, "rb") as f:
                _force_support[key] = _FORCE_MARKER in f.read()
        except OSError:
            _force_support[key] = False
    return _force_support[key]


_JCC = re.compile(r"^j(?!mp)[a-z]+$")


def _disasm(binary: Path) -> List[tuple]:
    out = subprocess.check_output(["objdump", "-d", "--no-show-raw-insn", str(binary)],
                                  text=True, stderr=subprocess.DEVNULL)
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        t = re.match(r"([0-9a-f]+) <", m.group(3))
        rows.append([int(m.group(1), 16), 0, m.group(2), int(t.group(1), 16) if t else None,
                     m.group(3)])
    for i in range(len(rows) - 1):
        rows[i][1] = rows[i + 1][0]
    return [tuple(r) for r in rows]


def _litmus_labels(binary: Path, stem: str) -> Dict[int, int]:
    safe = stem.replace("-", "_").replace(".", "_")
    prefix = f"__litmus_{safe}_pc"
    out = subprocess.check_output(["nm", "--defined-only", str(binary)], text=True)
    labels = {}
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[-1].startswith(prefix) and parts[-1][len(prefix):].isdigit():
            labels[int(parts[-1][len(prefix):])] = int(parts[0], 16)
    return labels


def _reaches(rows_by_addr: dict, addrs: list, start: int, dest: int) -> bool:
    import bisect
    hops = 0
    i = bisect.bisect_left(addrs, start)
    for _ in range(64):
        if i >= len(addrs):
            return False
        a = addrs[i]
        if a == dest:
            return True
        r = rows_by_addr[a]
        if r[2].startswith("jmp") and r[3] is not None and hops < 4:
            hops += 1
            i = bisect.bisect_left(addrs, r[3])
            continue
        if r[2].startswith(("j", "call", "ret")):
            return False
        i += 1
    return False


def _arch_taken(rows: list, idx: int) -> Optional[bool]:
    if idx < 2:
        return None
    x, t, j = rows[idx - 2], rows[idx - 1], rows[idx]
    rx = re.fullmatch(r"(%\w+),(%\w+)", x[4].replace(" ", ""))
    rt = re.fullmatch(r"(%\w+),(%\w+)", t[4].replace(" ", ""))
    if not (x[2].startswith("xor") and t[2].startswith("test") and rx and rt
            and rx.group(1) == rx.group(2) and rt.group(1) == rt.group(2)
            and rx.group(1)[-2:] == rt.group(1)[-2:]):
        return None
    if j[2] in ("je", "jz"):
        return True
    if j[2] in ("jne", "jnz"):
        return False
    return None


def branch_force_plan(binary: Path, ann: dict) -> List[dict]:
    rows = _disasm(binary)
    rows_by_addr = {r[0]: r for r in rows}
    index = {r[0]: i for i, r in enumerate(rows)}
    addrs = sorted(rows_by_addr)
    stem = binary.name
    labels = _litmus_labels(binary, stem)
    plan = []
    for e in ann.get("annotations", []):
        if "branch_addr" not in e:
            continue
        ba = int(e["branch_addr"])
        p = dict(branch_pc=e.get("branch_pc"), addr=ba, mode=e.get("mode"))
        r = rows_by_addr.get(ba)
        dest = labels.get(e.get("btb_forced_target_pc"))
        want_arch = e.get("mode") == "correctly_not_taken"
        arch = _arch_taken(rows, index[ba]) if r is not None else None
        p["arch_taken"] = arch
        if r is None or not _JCC.match(r[2]) or r[3] is None:
            p.update(force="unknown", why="no direct jcc at branch_addr")
        elif r[3] == r[1]:
            p.update(force="not_taken", fallthrough=r[1], static_target=r[3],
                     why="degenerate: target == fall-through")
        else:
            p.update(fallthrough=r[1], static_target=r[3], dest=dest)
            ft = tk = False
            if dest is not None:
                ft = _reaches(rows_by_addr, addrs, r[1], dest)
                tk = _reaches(rows_by_addr, addrs, r[3], dest)
            if ft and not tk:
                p["force"] = "not_taken"
            elif tk and not ft:
                p["force"] = "taken"
            elif arch is not None:
                taken = arch if want_arch else (not arch)
                p.update(force="taken" if taken else "not_taken",
                         why=f"from flags idiom (reach fallthrough={ft} taken={tk})")
            else:
                p.update(force="unknown", why=f"reach fallthrough={ft} taken={tk}, no flags idiom")
        if arch is not None and p["force"] in ("taken", "not_taken") and "degenerate" not in p.get("why", ""):
            p["consistent_with_arch"] = ((p["force"] == "taken") == arch) == want_arch
        plan.append(p)
    return plan


def _branch_ann_for_se(ann_path: Path, workdir: Path,
                       binary: Optional[Path] = None) -> Path:
    ann = json.loads(ann_path.read_text())
    for entry in ann.get("annotations", []):
        if "branch_addr" in entry and "branch_pc_addr" not in entry:
            entry["branch_pc_addr"] = entry["branch_addr"]
            entry["branch_pc_addr_hex"] = hex(int(entry["branch_addr"]))
    if binary is not None and binary_has_resolve_hooks(GEM5_BIN):
        plan = branch_force_plan(binary, ann)
        by_addr = {p["addr"]: p for p in plan}
        for entry in ann.get("annotations", []):
            p = by_addr.get(int(entry.get("branch_addr", -1)))
            if p is None:
                continue
            if p["force"] == "unknown":
                entry["orig_mode"] = entry.get("mode")
                entry["mode"] = "mispredict_not_taken"
                continue
            tgt = 1 if p["force"] == "not_taken" else p["static_target"]
            entry["orig_mode"] = entry.get("mode")
            entry["mode"] = "simspect_force"
            entry["btb_forced_target_addr"] = tgt
            entry["btb_forced_target_addr_hex"] = hex(tgt)
            entry.pop("btb_forced_target_x86_offset", None)
            entry.pop("btb_forced_target_x86_offset_hex", None)
        (workdir / "force_plan.json").write_text(json.dumps(plan, indent=1))
    out = workdir / "branch_ann_se.json"
    out.write_text(json.dumps(ann, indent=1))
    return out


def run_gem5(binary: Path, workdir: Path,
             ann_path: Optional[Path] = None,
             fnc_pc: Optional[int] = None) -> Path:
    outdir = workdir / "m5out"
    outdir.mkdir(exist_ok=True)
    dbg_flags = (GEM5_DBG_FLAG if "Commit" in GEM5_DBG_FLAG.split(",")
                 else GEM5_DBG_FLAG + ",Commit")
    cmd = [
        str(GEM5_BIN),
        f"--outdir={outdir}",
        f"--debug-flags={dbg_flags}",
        f"--debug-file={GEM5_DBG_FILE}",
        str(SE_CONFIG),
        f"--cmd={binary}",
        f"--cpu-type={GEM5_CPU}",
        "--caches",
        f"--scheme={_scheme}",
    ]

    if GEM5_MAX_TICK > 0:
        cmd.append(f"--abs-max-tick={GEM5_MAX_TICK}")

    if BRANCH_ANN_ENABLE and ann_path is not None and ann_path.exists():
        base = _func_base_addr(binary, binary.stem)
        cmd.append(f"--branch-ann-file={_branch_ann_for_se(ann_path, workdir, binary)}")
        if base is not None:
            cmd.append(f"--branch-ann-base={hex(base)}")


    if ALLOW_LEAKED:
        cmd.append("--allow_leaked")

    if fnc_pc is not None and FNC_COMMIT_STALL_CYCLES > 0:
        cmd.append(f"--fnc-commit-stall-pc={hex(fnc_pc)}")
        cmd.append(f"--fnc-commit-stall-cycles={FNC_COMMIT_STALL_CYCLES}")

    extra = os.environ.get("SIMSPECT_GEM5_EXTRA", "")
    if extra:
        cmd.extend(a for a in extra.split("\x1f") if a)

    _run_bounded(cmd)
    return outdir / GEM5_DBG_FILE


def _set_pdeathsig():
    PR_SET_PDEATHSIG = 1
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(PR_SET_PDEATHSIG,
                                                   signal.SIGKILL)


def _run_bounded(cmd: list) -> None:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=str(GEM5_DIR), start_new_session=True,
                            preexec_fn=_set_pdeathsig)
    try:
        out, err = proc.communicate(timeout=GEM5_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise RuntimeError(
            f"gem5 timed out after {GEM5_TIMEOUT_S}s (runaway/livelock) — killed")
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, out, err)


_GLUE_BEFORE_TICK_RE = re.compile(r"^[^\s\d]+(?=\s*\d+: )")


def _unglue(line: str) -> str:
    if line.startswith("O3PipeView:"):
        return line
    i = line.find("O3PipeView:")
    if i > 0:
        return line[i:]
    return _GLUE_BEFORE_TICK_RE.sub("", line, count=1)


def _trace_lines(trace_path: Path):
    with open(trace_path) as f:
        for line in f:
            yield _unglue(line)


def parse_pipeview(trace_path: Path) -> Dict[int, List[dict]]:
    by_pc: Dict[int, List[dict]] = defaultdict(list)
    cur = None
    for line in _trace_lines(trace_path):
        if not line.startswith("O3PipeView:"):
            continue
        parts = line.rstrip().split(":")
        stage = parts[1]
        if stage == "fetch":
            cur = dict(pc=int(parts[3], 16),
                       fetch=int(parts[2]), decode=0, rename=0, dispatch=0,
                       issue=0, complete=0, retire=0)
        elif stage in ("decode", "rename", "dispatch", "issue", "complete"):
            if cur:
                cur[stage] = int(parts[2])
        elif stage == "retire":
            if cur:
                cur["retire"] = int(parts[2])
                by_pc[cur["pc"]].append(cur)
                cur = None
    return dict(by_pc)


SIMSPECT_PREFIX = "O3PipeView:simspect:"
_SIMSPECT_HEX_FIELDS = ("line", "pc", "victim")
_SIMSPECT_INT_FIELDS = ("seq", "cause", "sq", "id")


def _simspect_val(key: str, val: str):
    if val in ("-", ""):
        return None
    if key in _SIMSPECT_HEX_FIELDS:
        return int(val, 16)
    if key in _SIMSPECT_INT_FIELDS:
        return int(val, 0)
    return val


def parse_simspect_line(line: str) -> Optional[dict]:
    line = _unglue(line)
    if not line.startswith(SIMSPECT_PREFIX):
        return None
    parts = line.rstrip("\n").rstrip("\r").split(":")
    if len(parts) < 5:
        raise ValueError(f"malformed simspect line: {line!r}")
    ev = dict(tick=int(parts[2]), struct=parts[3], kind=parts[4],
              line=None, seq=None, pc=None, victim=None, cause=None,
              sq=None, id=None)
    for field in parts[5:]:
        if "=" not in field:
            raise ValueError(f"malformed simspect field {field!r} in {line!r}")
        k, v = field.split("=", 1)
        ev[k] = _simspect_val(k, v)
    return ev


def parse_simspect_events(trace_path: Path) -> List[dict]:
    events: List[dict] = []
    for raw in _trace_lines(trace_path):
        ev = parse_simspect_line(raw)
        if ev is not None:
            ev["order"] = len(events)
            events.append(ev)
    return events


def parse_pipeview_by_seq(trace_path: Path) -> Dict[int, dict]:
    by_seq: Dict[int, dict] = {}
    cur = None
    for line in _trace_lines(trace_path):
        if not line.startswith("O3PipeView:") or line.startswith(SIMSPECT_PREFIX):
            continue
        parts = line.rstrip().split(":")
        stage = parts[1]
        if stage == "fetch":
            try:
                seq = int(parts[5])
            except (IndexError, ValueError):
                cur = None
                continue
            cur = dict(seq=seq, pc=int(parts[3], 16), upc=int(parts[4]),
                       fetch=int(parts[2]), decode=0, rename=0, dispatch=0,
                       issue=0, complete=0, retire=0)
        elif stage in ("decode", "rename", "dispatch", "issue", "complete"):
            if cur:
                cur[stage] = int(parts[2])
        elif stage == "retire":
            if cur:
                cur["retire"] = int(parts[2])
                by_seq[cur["seq"]] = cur
                cur = None
    return by_seq


def parse_lsq(trace_path: Path) -> Dict[int, List[dict]]:
    by_pc: Dict[int, List[dict]] = defaultdict(list)
    by_sn: Dict[int, dict] = {}
    insert_re  = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+Inserting load PC \(0x([0-9a-f]+)=>")
    execute_re = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+Executing load PC \(0x([0-9a-f]+)=>")
    squash_re  = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+Load Instruction PC \(0x([0-9a-f]+)=>.*squashed,\s*\[sn:(\d+)\]")
    packet_re  = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+successfully sent out packet\(s\) for inst \[sn:(\d+)\]")
    spec_re    = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+send a spec read for inst \[sn:(\d+)\]")
    expose_re  = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+Validate/Expose request for inst \[sn:(\d+)\]")
    memaccess_re = re.compile(r"^\s*(\d+):\s+system\.cpu\.iew\.lsq\..*:\s+Doing memory access for inst \[sn:(\d+)\]")
    dcache_read_re = re.compile(
        r"^\s*(\d+):\s+system\.cpu\.dcache:\s+access for ReadReq \[[0-9a-f]+:[0-9a-f]+\]\s+(hit|miss)")
    pending_read_sn = None
    speclfb_usl_re = re.compile(
        r"^\s*(\d+):.*Initiating Translation inst \[sn:(\d+)\] sPC [0-9a-f]+ - "
        r"Prior Brs Not Resolved\. isCUSL: ([01])\..*?isUnsafe: ([01])")
    insert_sn_re  = re.compile(r"\[sn:(\d+)\]")
    for line in _trace_lines(trace_path):
        m = insert_re.match(line)
        if m:
            tick = int(m.group(1)); pc = int(m.group(2), 16)
            sn_m = insert_sn_re.search(line)
            sn = int(sn_m.group(1)) if sn_m else -1
            rec = dict(pc=pc, sn=sn, insert_tick=tick, execute_tick=0,
                       squash_tick=0, packet_tick=0, spec_read_tick=0,
                       expose_tick=0, memaccess_tick=0, cache_fill_tick=0,
                       cache_access_outcome="",
                       spec_cusl=False, spec_unprotected=False)
            by_sn[sn] = rec
            by_pc[pc].append(rec)
            continue
        m = execute_re.match(line)
        if m:
            tick = int(m.group(1)); pc = int(m.group(2), 16)
            sn_m = insert_sn_re.search(line)
            sn = int(sn_m.group(1)) if sn_m else -1
            rec = by_sn.get(sn)
            if rec is not None:
                rec["execute_tick"] = tick
            continue
        m = packet_re.match(line)
        if m:
            rec = by_sn.get(int(m.group(2)))
            if rec is not None and rec["packet_tick"] == 0:
                rec["packet_tick"] = int(m.group(1))
            continue
        m = spec_re.match(line)
        if m:
            rec = by_sn.get(int(m.group(2)))
            if rec is not None and rec["spec_read_tick"] == 0:
                rec["spec_read_tick"] = int(m.group(1))
            continue
        m = expose_re.match(line)
        if m:
            rec = by_sn.get(int(m.group(2)))
            if rec is not None and rec["expose_tick"] == 0:
                rec["expose_tick"] = int(m.group(1))
            continue
        m = memaccess_re.match(line)
        if m:
            sn = int(m.group(2))
            rec = by_sn.get(sn)
            if rec is not None and rec["memaccess_tick"] == 0:
                rec["memaccess_tick"] = int(m.group(1))
            pending_read_sn = sn
            continue
        m = dcache_read_re.match(line)
        if m and pending_read_sn is not None:
            rec = by_sn.get(pending_read_sn)
            if rec is not None and rec["cache_access_outcome"] == "":
                rec["cache_access_outcome"] = m.group(2)
                if m.group(2) == "miss":
                    rec["cache_fill_tick"] = int(m.group(1))
            pending_read_sn = None
            continue
        m = speclfb_usl_re.match(line)
        if m:
            rec = by_sn.get(int(m.group(2)))
            if rec is not None and m.group(3) == "1":
                rec["spec_cusl"] = True
                if m.group(4) == "0":
                    rec["spec_unprotected"] = True
            continue
        m = squash_re.match(line)
        if m:
            tick = int(m.group(1)); pc = int(m.group(2), 16); sn = int(m.group(3))
            rec = by_sn.get(sn)
            if rec is not None:
                rec["squash_tick"] = tick
    return dict(by_pc)


_COMMIT_SQUASH_RE = re.compile(
    r"^\s*(\d+):\s+system\.cpu\.commit.*Squashing due to branch mispred PC:(0x[0-9a-f]+)")


def parse_commit_squashes(trace_path: Path) -> Dict[int, List[int]]:
    by_pc: Dict[int, List[int]] = defaultdict(list)
    for line in _trace_lines(trace_path):
        m = _COMMIT_SQUASH_RE.match(line)
        if m:
            by_pc[int(m.group(2), 16)].append(int(m.group(1)))
    return {pc: sorted(t) for pc, t in by_pc.items()}


_COMMIT_INST_RE = re.compile(
    r"^\s*(\d+):\s+system\.cpu\.commit.*Committing instruction with \[sn:\d+\] PC \((0x[0-9a-f]+)=>")


def parse_commit_ticks(trace_path: Path) -> Dict[int, List[int]]:
    by_pc: Dict[int, List[int]] = defaultdict(list)
    for line in _trace_lines(trace_path):
        m = _COMMIT_INST_RE.match(line)
        if m:
            by_pc[int(m.group(2), 16)].append(int(m.group(1)))
    return {pc: sorted(t) for pc, t in by_pc.items()}


def fill_retire_from_commit(by_pc: Dict[int, list], commit_by_pc: Dict[int, List[int]],
                            pcs: List[Optional[int]]) -> List[str]:
    filled = []
    for pc in pcs:
        if pc is None or not commit_by_pc.get(pc):
            continue
        if any(r.get("retire", 0) > 0 for r in by_pc.get(pc, [])):
            continue
        by_pc.setdefault(pc, []).append(dict(pc=pc, fetch=0, decode=0, rename=0, dispatch=0, issue=0,
                                             complete=0, retire=min(commit_by_pc[pc]), source="commit_trace"))
        filled.append(hex(pc))
    return filled


def best_record(recs: List[dict]) -> Optional[dict]:
    ORDER = ["fetch", "decode", "rename", "dispatch", "issue", "complete", "retire"]
    def score(r):
        for s in reversed(ORDER):
            if r[s] > 0:
                return (ORDER.index(s), r["retire"], r["complete"])
        return (-1, 0, 0)
    return max(recs, key=score) if recs else None


def load_annotation(ann_path: Path) -> dict:
    ann = json.loads(ann_path.read_text())
    return dict(
        xmit=ann.get("xmit", {}),
        lc=ann.get("commit_boundary", {}).get("last_committed", {}),
        fnc=ann.get("commit_boundary", {}).get("first_noncommitted", {}),
        annotations=ann.get("annotations", []),
    )


_DIVIDE_FAULT_RE = re.compile(
    r"panic:\s+fault\s+\(Divide-Error\).*?PC\s*\(0x([0-9a-f]+)",
    re.IGNORECASE,
)


def _alloy_pc_at_offset(parts: dict, offset: int) -> Optional[int]:
    pc_offs: Dict[int, int] = {}
    for a in parts.get("annotations", []):
        pc = a.get("branch_pc")
        off = a.get("x86_pc_offset")
        if pc is not None and off is not None:
            pc_offs[pc] = off
    for which in (parts.get("lc"), parts.get("fnc"), parts.get("xmit")):
        if which:
            pc = which.get("pc")
            off = which.get("x86_offset")
            if pc is not None and off is not None:
                pc_offs[pc] = off
    if not pc_offs:
        return None
    sorted_pcs = sorted(pc_offs.items(), key=lambda kv: kv[1])
    for i, (pc, off) in enumerate(sorted_pcs):
        next_off = sorted_pcs[i + 1][1] if i + 1 < len(sorted_pcs) else 1 << 30
        if off <= offset < next_off:
            return pc
    return None


def classify_divide_panic(stderr: str, parts: dict, xmit_pc: Optional[int],
                          xmit_kind: str) -> Optional[dict]:
    if not xmit_pc or xmit_kind != "other_x":
        return None
    m = _DIVIDE_FAULT_RE.search(stderr)
    if not m:
        return None
    fault_addr = int(m.group(1), 16)
    xmit_x86_off = parts.get("xmit", {}).get("x86_offset")
    if xmit_x86_off is None:
        return None
    base = xmit_pc - xmit_x86_off
    fault_off = fault_addr - base
    fault_pc = _alloy_pc_at_offset(parts, fault_off)
    xmit_alloy_pc = parts.get("xmit", {}).get("pc")
    if fault_pc is None or fault_pc != xmit_alloy_pc:
        return None
    mispredict_pcs = [a.get("branch_pc") for a in parts.get("annotations", [])
                      if a.get("mode") in ("mispredict_not_taken",
                                           "mispredict_taken")
                      and a.get("branch_pc") is not None]
    if not mispredict_pcs or xmit_alloy_pc <= min(mispredict_pcs):
        return None
    return dict(
        status="ok",
        issued_in_window=True,
        hit_kind="div_fault",
        error=None,
    )


def parse_ticks_per_cycle(outdir: Path) -> int:
    cfg = json.loads((outdir / "config.json").read_text())
    try:
        clk = cfg["system"]["cpu_clk_domain"]["clock"]
        return int(clk[0]) if isinstance(clk, list) else int(clk)
    except (KeyError, TypeError):
        return 500


def collect_unresolved_branches(ann_full: dict, binary: Path,
                                func_name: str) -> List[dict]:
    out: List[dict] = []
    base = None
    for e in ann_full.get("annotations", []):
        stall = int(e.get("resolve_stall_cycles", 0) or 0)
        if stall <= 0:
            continue
        if e.get("mode") == "correctly_not_taken":
            continue
        addr = e.get("branch_addr")
        if addr is None:
            bxo = e.get("x86_branch_offset")
            if bxo is None:
                continue
            if base is None:
                base = _func_base_addr(binary, func_name)
                if base is None:
                    return out
            addr = base + int(bxo)
        out.append(dict(pc=int(addr), stall_cycles=stall))
    return out


def parse_branch_events(trace_path: Path) -> Dict[int, Dict[int, dict]]:
    out: Dict[int, Dict[int, dict]] = defaultdict(dict)
    for ev in parse_simspect_events(trace_path):
        if ev["struct"] != "BR" or ev["pc"] is None or ev["seq"] is None:
            continue
        d = out[ev["pc"]].setdefault(ev["seq"], {})
        d.setdefault(ev["kind"], ev["tick"])
        for k in ("stall", "fire", "mispred", "taken", "target", "upc"):
            if isinstance(ev.get(k), str):
                d[f"{ev['kind']}_{k}"] = int(ev[k], 0)
    return dict(out)


def _resolution_of(seqs: Dict[int, dict]) -> Optional[dict]:
    live = {q: d for q, d in seqs.items() if "resolve_drop" not in d
            and ("resolve_hold" in d or "resolve_visible" in d)}
    if live:
        q = max(live)
        return dict(seq=q, **live[q])
    if seqs:
        q = max(seqs)
        return dict(seq=q, **seqs[q])
    return None


def check_branch_resolutions(by_pc: Dict[int, list],
                             xmit_complete: int,
                             unresolved: List[dict],
                             ticks_per_cycle: int) -> Tuple[bool, List[dict]]:
    details: List[dict] = []
    all_ok = True
    for u in unresolved:
        rec = best_record(by_pc.get(u["pc"], []))
        complete = rec.get("complete", 0) if rec else 0
        br = u.get("br")
        if br is not None:
            r = _resolution_of(br)
            d = dict(pc=hex(u["pc"]), stall=u["stall_cycles"], source="observed",
                     complete=complete)
            if r is None:
                d.update(resolve_tick=0, ok=True, reason="never fetched")
            else:
                d.update(seq=r["seq"], hold_tick=r.get("resolve_hold", 0),
                         release_tick=r.get("resolve_release", 0),
                         visible_tick=r.get("resolve_visible", 0),
                         dropped="resolve_drop" in r,
                         stall_applied=("resolve_hold" in r) or not (
                             "resolve_visible" in r or "resolve_release" in r),
                         estimate_tick=(complete + u["stall_cycles"] * ticks_per_cycle
                                        if complete else 0))
                tick = d["visible_tick"] or d["release_tick"]
                d["resolve_tick"] = tick
                if tick == 0:
                    d.update(ok=True, reason="never resolved (dropped or sim ended)")
                else:
                    d["ok"] = xmit_complete < tick
            details.append(d)
            all_ok &= d["ok"]
            continue
        if complete == 0:
            details.append(dict(pc=hex(u["pc"]), stall=u["stall_cycles"],
                                complete=0, prop_tick=0, ok=True, source="estimate",
                                reason="not completed"))
            continue
        prop_tick = complete + u["stall_cycles"] * ticks_per_cycle
        ok = xmit_complete < prop_tick
        details.append(dict(pc=hex(u["pc"]), stall=u["stall_cycles"],
                            complete=complete, prop_tick=prop_tick, ok=ok,
                            source="estimate"))
        if not ok:
            all_ok = False
    return all_ok, details


def execution_validity(ann_entries: List[dict], br_events: Dict[int, Dict[int, dict]],
                       by_seq: Dict[int, dict], xmit_pc: Optional[int],
                       plan: Optional[List[dict]]) -> dict:
    out: dict = dict(resolved_correct=None, window_opened=None, stall_applied=None,
                     force_applied=None, notes=[])
    if not br_events:
        return out
    retired = {q for q, r in by_seq.items() if r.get("retire", 0) > 0}
    res, unr = [], []
    for e in ann_entries:
        if "branch_addr" not in e:
            continue
        pc = int(e["branch_addr"])
        (res if e.get("mode") == "correctly_not_taken" else unr).append(
            (pc, int(e.get("resolve_stall_cycles", 0) or 0), e.get("branch_pc", pc)))
    if res:
        bad = [hex(pc) for pc, _, _ in res for q, d in br_events.get(pc, {}).items()
               if q in retired and d.get("resolve_visible_mispred") == 1]
        out["resolved_correct"] = not bad
        if bad:
            out["notes"].append(f"resolved branch mispredicted: {bad}")
    nonx = [pc for pc, _, _ in sorted((u for u in unr if u[0] != xmit_pc), key=lambda u: u[2])]
    if nonx:
        first = nonx[0]
        inst = [d for q, d in br_events.get(first, {}).items() if q in retired]
        out["window_opened"] = any(d.get("resolve_visible_mispred") == 1 for d in inst)
        if not out["window_opened"]:
            out["notes"].append(f"oldest unresolved branch {hex(first)} did not mispredict")
    stalled = [pc for pc, st, _ in unr if st > 0 and pc != xmit_pc]
    if stalled:
        miss = [hex(pc) for pc in stalled for q, d in br_events.get(pc, {}).items()
                if ("resolve_visible" in d or "resolve_release" in d) and "resolve_hold" not in d]
        out["stall_applied"] = not miss
        if miss:
            out["notes"].append(f"resolve stall not registered at {miss}")
    if plan:
        want = {p["addr"]: int(p["force"] == "taken") for p in plan
                if p.get("force") in ("taken", "not_taken")}
        miss = [hex(pc) for pc, tk in want.items() for q, d in br_events.get(pc, {}).items()
                if "resolve_visible" in d and ("predict_force" not in d
                                               or d.get("predict_force_taken") != tk)]
        out["force_applied"] = not miss
        if miss:
            out["notes"].append(f"forced prediction missing or wrong direction at {miss}")
        inc = [hex(p["addr"]) for p in plan if p.get("consistent_with_arch") is False]
        if inc:
            out["force_applied"] = False
            out["notes"].append(f"force plan contradicts the flags idiom at {inc}")
        unk = [hex(p["addr"]) for p in plan if p.get("force") == "unknown"]
        if unk:
            out["notes"].append(f"no force plan for {unk}")
    return out


CheckFn = Callable[[Dict[int, list], Optional[int], Optional[int], Optional[int],
                    List[dict], int, Dict[int, list], Dict[int, list]], dict]


def process_one(s_path: Path, ann_path: Path, check_fn: CheckFn,
                keep_tmp: bool = False) -> dict:
    name    = s_path.stem
    workdir = Path(tempfile.mkdtemp(prefix=f"gem5_{name}_"))
    result  = dict(name=name, status="ok",
                   xmit_pc=None, last_committed_pc=None, first_noncommitted_pc=None,
                   xmit_kind=None, issued_in_window=None,
                   xmit_issue=None, xmit_complete=None,
                   lc_retire=None, fnc_retire=None, fnc_complete=None,
                   error=None)
    parts: dict = {}
    xmit_pc: Optional[int] = None
    try:
        parts   = load_annotation(ann_path)
        xmit    = parts["xmit"]
        lc      = parts["lc"]
        fnc     = parts["fnc"]

        result["xmit_kind"] = xmit.get("kind", "")

        if str(Path(__file__).resolve().parent) not in sys.path:
            sys.path.append(str(Path(__file__).resolve().parent))
        import cache_setup as _cs
        _cs_used = _cs.resolve(CACHE_SETUP, name, gem5_bin=str(GEM5_BIN))
        result["cache_setup"] = _cs_used
        if CACHE_SETUP in _cs.META:
            result["cache_setup_mode"] = CACHE_SETUP
            result["cache_setup_seed"] = _cs.current_seed()
        if CACHE_SETUP == "random_all":
            result["cache_setup_choices"] = list(_cs.allowed_setups(str(GEM5_BIN)))
        binary, ann_path, cs_info = _cs.prepare(s_path, ann_path, workdir, build_binary,
                                                _cs_used)
        if cs_info is not None:
            result["cache_setup_info"] = cs_info
            parts = load_annotation(ann_path)
            xmit, lc, fnc = parts["xmit"], parts["lc"], parts["fnc"]
        xmit_pc = resolve_pc(binary, name, xmit)
        lc_pc   = resolve_pc(binary, name, lc)
        fnc_pc  = resolve_pc(binary, name, fnc)

        result["xmit_pc"]               = hex(xmit_pc) if xmit_pc else None
        result["last_committed_pc"]     = hex(lc_pc)   if lc_pc   else None
        result["first_noncommitted_pc"] = hex(fnc_pc)  if fnc_pc  else None

        if xmit_pc is None:
            result["status"] = "warn"
            result["error"]  = "no xmit x86 PC"
        else:
            trace = run_gem5(binary, workdir, ann_path=ann_path, fnc_pc=fnc_pc)
            by_pc     = parse_pipeview(trace)
            result["retire_from_commit_trace"] = fill_retire_from_commit(
                by_pc, parse_commit_ticks(trace), [lc_pc, fnc_pc])
            lsq_by_pc = parse_lsq(trace)
            squash_by_pc = parse_commit_squashes(trace)
            ticks_per_cycle = parse_ticks_per_cycle(workdir / "m5out")
            unresolved = collect_unresolved_branches(
                dict(annotations=parts["annotations"]), binary, name)
            unresolved = [u for u in unresolved if u["pc"] != xmit_pc]
            br_events = parse_branch_events(trace)
            if br_events:
                for u in unresolved:
                    u["br"] = br_events.get(u["pc"], {})
            plan_f = workdir / "force_plan.json"
            plan = json.loads(plan_f.read_text()) if plan_f.exists() else None
            result["force_plan"] = plan
            result["br_resolve_source"] = "observed" if br_events else "estimate"
            result["br_events"] = {hex(pc): {str(q): d for q, d in seqs.items()}
                                   for pc, seqs in br_events.items()}
            if getattr(check_fn, "wants_trace", False):
                check_result = check_fn(by_pc, xmit_pc, lc_pc, fnc_pc,
                                        unresolved, ticks_per_cycle, lsq_by_pc,
                                        squash_by_pc, trace_path=trace)
            else:
                check_result = check_fn(by_pc, xmit_pc, lc_pc, fnc_pc,
                                        unresolved, ticks_per_cycle, lsq_by_pc,
                                        squash_by_pc)
            result.update(check_result)
            validity = execution_validity(parts["annotations"], br_events,
                                          parse_pipeview_by_seq(trace) if br_events else {},
                                          xmit_pc, plan)
            result["validity"] = validity
            crit = result.setdefault("criteria", {})
            sig = result.get("xmit_signal") or 0
            rb = []
            for e in parts["annotations"]:
                if e.get("mode") != "correctly_not_taken" or "branch_addr" not in e:
                    continue
                r = _resolution_of(br_events.get(int(e["branch_addr"]), {})) if br_events else None
                vt = (r or {}).get("resolve_visible", 0)
                rb.append(dict(pc=hex(int(e["branch_addr"])), visible_tick=vt,
                               stall=int(e.get("resolve_stall_cycles", 0) or 0),
                               before_signal=(bool(vt) and sig > 0 and vt < sig)))
            result["resolved_branches"] = rb
            result["resolved_before_signal"] = (all(b["before_signal"] for b in rb)
                                              if (rb and br_events and sig) else None)
            for k in ("resolved_correct", "window_opened", "stall_applied", "force_applied"):
                crit[k] = validity[k]
            if any(validity[k] is False for k in
                   ("resolved_correct", "window_opened", "stall_applied", "force_applied")):
                result["issued_in_window_unvalidated"] = result.get("issued_in_window")
                result["issued_in_window"] = False
                result["status"] = "invalid"
                result["error"] = "; ".join(validity["notes"])

    except subprocess.CalledProcessError as e:
        result["status"] = "error"
        stderr = (e.stderr or b"").decode(errors="replace")
        cause = next((ln.strip() for ln in stderr.splitlines()
                      if ln.startswith(("panic:", "fatal:"))), None)
        result["error"] = (cause + " | " if cause else "") + stderr[-400:]
        hit = classify_divide_panic(stderr, parts, xmit_pc,
                                    result.get("xmit_kind", ""))
        if hit is not None:
            result.update(hit)
    except Exception as e:
        result["status"] = "error"
        result["error"]  = str(e)
    finally:
        if not keep_tmp:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            result["workdir"] = str(workdir)

    return result


def _tag(v):
    return {True: "YES", False: "NO ", None: "???"}[v]


def run_batch(check_fn: CheckFn, description: str = "window check") -> None:
    ap = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input_dir", type=Path)
    ap.add_argument("--jobs",     type=int, default=1)
    ap.add_argument("--keep-tmp", action="store_true")
    ap.add_argument("--out",      type=Path, default=None)
    ap.add_argument("--scheme",   type=int, default=2,
                    help="gem5 --scheme value (default: 2)")
    ap.add_argument("--limit",    type=int, default=None,
                    help="Only process the first N tests")
    args = ap.parse_args()

    global _scheme
    _scheme = args.scheme

    input_dir = args.input_dir.resolve()
    if not input_dir.is_dir():
        sys.exit(f"error: {input_dir} is not a directory")

    pairs = []
    for s_path in sorted(input_dir.glob("*.s")):
        ann_path = s_path.with_suffix(".ann.json")
        if ann_path.exists():
            pairs.append((s_path, ann_path))

    if not pairs:
        sys.exit("error: no .s / .ann.json pairs found")

    if args.limit:
        pairs = pairs[:args.limit]

    print(f"Found {len(pairs)} test(s) in {input_dir}")
    print(f"gem5 scheme={_scheme}  jobs={args.jobs}  check={description}\n")

    results: List[dict] = []

    def _run(pair: Tuple[Path, Path]) -> dict:
        s, a = pair
        r = process_one(s, a, check_fn, args.keep_tmp)
        tag  = _tag(r["issued_in_window"])
        xpc  = r["xmit_pc"] or "n/a"
        kind = r["xmit_kind"] or "?"
        lc_t = r.get("lc_retire", 0)    or 0
        xc_t = r.get("xmit_complete", 0) or 0
        fn_t = r.get("fnc_retire", 0)   or 0
        print(f"  [{tag}] {r['name']:20s}  xmit={xpc}({kind})"
              f"  lc_ret={lc_t}  xmit_cmp={xc_t}  fnc_ret={fn_t}  [{r['status'].upper()}]"
              + (f"  {r['error'][:60]}" if r.get("error") else ""))
        return r

    if args.jobs == 1:
        for pair in pairs:
            results.append(_run(pair))
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futs = {pool.submit(process_one, s, a, check_fn, args.keep_tmp): (s, a)
                    for s, a in pairs}
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                tag  = _tag(r["issued_in_window"])
                xpc  = r["xmit_pc"] or "n/a"
                kind = r["xmit_kind"] or "?"
                lc_t = r.get("lc_retire", 0)    or 0
                xc_t = r.get("xmit_complete", 0) or 0
                fn_t = r.get("fnc_retire", 0)   or 0
                print(f"  [{tag}] {r['name']:20s}  xmit={xpc}({kind})"
                      f"  lc_ret={lc_t}  xmit_cmp={xc_t}  fnc_ret={fn_t}"
                      + (f"  ERROR: {r['error'][:60]}" if r.get("error") else ""))

    yes = sum(1 for r in results if r["issued_in_window"] is True)
    no  = sum(1 for r in results if r["issued_in_window"] is False)
    err = sum(1 for r in results if r["status"] != "ok")
    print(f"\nResults: {yes} in window  |  {no} not in window  |  {err} error(s)  (total {len(results)})")

    if args.out:
        args.out.write_text(json.dumps(results, indent=2))
        print(f"Full results written to {args.out}")


FAST_PATH = os.environ.get("SIMSPECT_FAST_PATH", "").lower() in ("1", "true", "yes", "on")
if FAST_PATH:
    if str(Path(__file__).resolve().parent) not in sys.path:
        sys.path.append(str(Path(__file__).resolve().parent))
    import gem5_fastpath as _gem5_fastpath
    _gem5_fastpath.install(sys.modules[__name__])
