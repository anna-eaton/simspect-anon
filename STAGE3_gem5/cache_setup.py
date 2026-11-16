from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


def addr_fields(obj, path=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if isinstance(v, (dict, list)):
                out.update(addr_fields(v, p))
            elif (k == "addr" or k.endswith("_addr")) and isinstance(v, int):
                out[p] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(addr_fields(v, f"{path}[{i}]"))
    return out


def key_paths(obj, path=""):
    s = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            s.add(f"{path}.{k}"); s |= key_paths(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            s |= key_paths(v, f"{path}[{i}]")
    return s

LINE = 64
DEFAULT = "warm"
BEGIN_LABEL = "__simspect_cachesetup_begin"
END_LABEL = "__simspect_cachesetup_end"


class CacheSetupError(RuntimeError):
    pass


def current() -> str:
    return (os.environ.get("SIMSPECT_CACHE_SETUP") or DEFAULT).strip().lower()


def _code(line: str) -> str:
    return line.split("#", 1)[0].strip()


def _safe(stem: str) -> str:
    return stem.replace("-", "_").replace(".", "_")


_ZERO_FILL_RE = re.compile(r"^movq\s+\$0,\s*(-?\d+)?\(%(rsp|rbp)\)$")


def find_barrier(lines: List[str], stem: str) -> int:
    fstart = next((i for i, l in enumerate(lines) if _code(l) == f'"{stem}":'), None)
    if fstart is None:
        raise CacheSetupError("function label not found")
    first_lab = next((i for i in range(fstart, len(lines))
                      if re.match(rf"^__litmus_{re.escape(_safe(stem))}_\w+:$", lines[i].strip())),
                     None)
    if first_lab is None:
        raise CacheSetupError("no __litmus_ label")
    mf = [i for i in range(fstart, first_lab) if _code(lines[i]) == "mfence"]
    if not mf:
        raise CacheSetupError("expected 1 prologue mfence, found 0")
    for i in range(mf[0] + 1, mf[-1]):
        c = _code(lines[i])
        if not c or c in ("mfence",) or c.startswith(".") or _ZERO_FILL_RE.match(c):
            continue
        raise CacheSetupError(f"expected 1 prologue mfence, found {len(mf)} "
                              f"with non-zero-fill code between them: {c!r}")
    j = mf[-1] + 1
    while j < len(lines) and not lines[j].strip():
        j += 1
    if j >= len(lines) or lines[j].strip() != "#NO_APP":
        raise CacheSetupError("prologue mfence not closed by #NO_APP")
    return j + 1


_MEM_RE = re.compile(r"(-?\d+)?\(%(rsp|rbp)(?:,|\))")


def frame_region(lines: List[str], stem: str, insert_at: int) -> dict:
    fstart = next(i for i, l in enumerate(lines) if _code(l) == f'"{stem}":')
    fend = next((i for i in range(fstart, len(lines)) if lines[i].strip().startswith(".Lfunc_end")),
                len(lines))
    pushes_before_fp = pushes_after_fp = 0
    fp = False
    align = 0
    sub = 0
    for l in lines[fstart + 1:insert_at]:
        s = _code(l)
        if not s or s.startswith(".") or s.endswith(":"):
            continue
        if s.startswith("pushq"):
            if fp:
                pushes_after_fp += 1
            else:
                pushes_before_fp += 1
            continue
        if re.fullmatch(r"movq\s+%rsp,\s*%rbp", s):
            if pushes_before_fp != 1:
                raise CacheSetupError("frame pointer set up after != 1 push")
            fp = True
            continue
        m = re.fullmatch(r"andq\s+\$-(\d+),\s*%rsp", s)
        if m:
            align = int(m.group(1))
            continue
        m = re.fullmatch(r"subq\s+\$(\d+),\s*%rsp", s)
        if m:
            sub += int(m.group(1))
            continue
        if re.search(r",\s*%(rsp|esp|rbp|ebp)$", s) or s.startswith(("popq", "leave", "call")):
            raise CacheSetupError(f"unexpected stack-pointer write before barrier: {s!r}")
    disps = {"rsp": [], "rbp": []}
    rip = []
    for l in lines[fstart + 1:fend]:
        s = _code(l)
        if "(%rip)" in s:
            rip.append(s)
        for m in _MEM_RE.finditer(s):
            disps[m.group(2)].append(int(m.group(1) or 0))
    if rip:
        raise CacheSetupError(f"rip-relative data reference not supported: {rip[0]!r}")
    if fp:
        if align and align & (align - 1):
            raise CacheSetupError(f"odd stack alignment {align}")
        lo = -(8 * pushes_after_fp + max(align - 1, 0) + sub)
        reg = dict(base="rbp", lo=lo, hi=16, shape="A_frame_pointer",
                   pushes=pushes_after_fp, align=align, sub=sub)
        if align:
            bad = [d for d in disps["rsp"] if not 0 <= d < sub]
        else:
            off = -(8 * pushes_after_fp + sub)
            bad = [d for d in disps["rsp"] if not lo <= d + off < 16]
        if bad:
            raise CacheSetupError(f"rsp displacement outside the frame: {bad[:3]}")
        bad = [d for d in disps["rbp"] if not lo <= d < 16]
        if bad:
            raise CacheSetupError(f"rbp displacement outside the frame: {bad[:3]}")
    else:
        if disps["rbp"]:
            raise CacheSetupError("rbp-relative operand without a frame pointer")
        hi = sub + 8 * pushes_before_fp + 8
        lo = -128 if any(d < 0 for d in disps["rsp"]) else 0
        bad = [d for d in disps["rsp"] if not lo <= d < hi]
        if bad:
            raise CacheSetupError(f"rsp displacement outside the frame: {bad[:3]}")
        reg = dict(base="rsp", lo=lo, hi=hi, shape="B_no_frame_pointer",
                   pushes=pushes_before_fp, align=0, sub=sub)
    return reg


def line_probe_offsets(lo: int, hi: int) -> List[int]:
    offs, o = [], hi - 1
    while o > lo:
        offs.append(o)
        o -= LINE
    offs.append(lo)
    return sorted(set(offs))


PACE_LEAS = 64


def _cold(frame: dict) -> List[str]:
    b = frame["base"]
    out = ["\t.pushsection .bss", "\t.p2align 6", "__simspect_cs_save:", "\t.zero 64",
           "__simspect_cs_zero:", "\t.zero 64", "\t.popsection",
           "\tmovq\t%rax, __simspect_cs_save(%rip)"]
    for o in line_probe_offsets(frame["lo"], frame["hi"]):
        out.append("\tmovq\t__simspect_cs_zero(%rip), %rax")
        out += ["\tleaq\t(%rax,%rax), %rax"] * PACE_LEAS
        out += [f"\tclflush\t{o}(%{b},%rax)", "\tmfence"]
    out += ["\tmovq\t__simspect_cs_save(%rip), %rax", "\tmfence"]
    return out


PAGE = 4096
_SIZE_RE = re.compile(r"^(\d+)\s*([kKmM]?)([iI]?[bB])?$")


def parse_size(txt: str) -> int:
    m = _SIZE_RE.match(str(txt).strip())
    if not m:
        raise CacheSetupError(f"cache_setup=full: cannot parse size {txt!r}")
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024 * 1024}[m.group(2).lower()]


def _extra_args() -> List[str]:
    e = os.environ.get("SIMSPECT_GEM5_EXTRA") or ""
    return [a for a in e.split("\x1f") if a]


def _last_flag(args: List[str], flag: str) -> Optional[str]:
    v = None
    for i, a in enumerate(args):
        if a.startswith(flag + "="):
            v = a.split("=", 1)[1]
        elif a == flag and i + 1 < len(args):
            v = args[i + 1]
    return v


def fill_config() -> dict:
    args = _extra_args()
    explicit = (os.environ.get("SIMSPECT_CACHE_SETUP_FILL_BYTES") or "").strip()
    l1d = _last_flag(args, "--l1d_size")
    assoc = _last_flag(args, "--l1d_assoc")
    line = int(_last_flag(args, "--cacheline_size") or LINE)
    if line != LINE:
        raise CacheSetupError(f"cache_setup=full: --cacheline_size={line}, only {LINE} supported")
    if explicit:
        n, src = parse_size(explicit), "gem5.cache_setup_fill_bytes"
    elif _last_flag(args, "--l0d_size"):
        raise CacheSetupError("cache_setup=full: this config has --l0d_size (Ruby MESI_Three_Level), so "
                              "--l1d_size is the second-level cache; set gem5.cache_setup_fill_bytes to "
                              "the size of the cache you want full (e.g. the L0D size)")
    elif l1d:
        n, src = parse_size(l1d), "--l1d_size"
    else:
        raise CacheSetupError("cache_setup=full needs the L1D size: set gem5.cache_setup_fill_bytes "
                              "or pass --l1d_size=<size> in gem5.extra_args (se.py defaults differ "
                              "between gem5 trees, so none is assumed)")
    if n <= 0 or n % LINE:
        raise CacheSetupError(f"cache_setup=full: fill size {n} is not a positive multiple of {LINE}")
    out = dict(fill_bytes=n, fill_source=src, l1d_size_arg=l1d, l1d_assoc_arg=assoc,
               n_loads=n // LINE)
    if assoc:
        a = int(assoc)
        if l1d and parse_size(l1d) % (a * LINE) == 0:
            way = parse_size(l1d) // a
            out.update(l1d_sets=way // LINE, set_cover_exact=(n == parse_size(l1d) and way <= PAGE))
    return out


def _full(frame: dict) -> List[str]:
    cfg = fill_config()
    out = ["\t.pushsection .bss", "\t.p2align 12", "__simspect_csf_buf:",
           f"\t.zero {cfg['fill_bytes']}", "__simspect_csf_save:", "\t.zero 64", "\t.popsection",
           "\tmovq\t%rax, __simspect_csf_save(%rip)"]
    for o in range(0, cfg["fill_bytes"], LINE):
        out.append(f"\tmovq\t__simspect_csf_buf+{o}(%rip), %rax")
    out += ["\tmovq\t__simspect_csf_save(%rip), %rax", "\tmfence"]
    return out


STRATEGIES: Dict[str, Callable[[dict], List[str]]] = {
    "cold": _cold,
    "full": _full,
}
RANDOM_CHOICES = ("warm", "cold")
RANDOM_ALL_ORDER = ("warm", "cold", "full")
META = ("random", "random_all")
KNOWN = ("warm",) + tuple(STRATEGIES) + META
DEFAULT_SEED = "simspect-cache-random-v1"


def current_seed() -> str:
    return (os.environ.get("SIMSPECT_CACHE_SETUP_SEED") or DEFAULT_SEED).strip()


def choose(stem: str, seed: Optional[str] = None) -> str:
    import hashlib
    stem = str(stem).split("__")[0]
    seed = current_seed() if seed is None else str(seed)
    h = hashlib.sha256(f"{seed}\0{stem}".encode()).digest()
    return RANDOM_CHOICES[h[0] & 1]


def _gem5_bin(gem5_bin: Optional[str]) -> str:
    b = gem5_bin if gem5_bin is not None else os.environ.get("SIMSPECT_GEM5_BIN", "")
    if not str(b).strip():
        raise CacheSetupError("cache_setup=random_all needs the gem5 binary path (to know which "
                              "setups the build allows); set SIMSPECT_GEM5_BIN or pass gem5_bin")
    return str(b)


def allowed_setups(gem5_bin: Optional[str] = None) -> Tuple[str, ...]:
    b = _gem5_bin(gem5_bin)
    no_flush = any(key in b for key in CLFLUSH_UNSUPPORTED)
    return tuple(x for x in RANDOM_ALL_ORDER if not (x == "cold" and no_flush))


def choose_all(stem: str, seed: Optional[str] = None, gem5_bin: Optional[str] = None) -> str:
    import hashlib
    stem = str(stem).split("__")[0]
    seed = current_seed() if seed is None else str(seed)
    choices = allowed_setups(gem5_bin)
    h = hashlib.sha256(f"{seed}\0{stem}".encode()).digest()
    return choices[int.from_bytes(h[:8], "big") % len(choices)]


def resolve(strategy: str, stem: str, seed: Optional[str] = None,
            gem5_bin: Optional[str] = None) -> str:
    if strategy == "random":
        return choose(stem, seed)
    if strategy == "random_all":
        return choose_all(stem, seed, gem5_bin)
    return strategy

CLFLUSH_UNSUPPORTED = {
    "amulet-gem5-InvisiSpec_AE": "Ruby MESI_Two_Level ignores clflush (no CleanInvalidReq->FLUSH "
                                 "conversion in RubyPort; no Ruby request, L1D misses unchanged)",
    "amulet-gem5-STT_AE": "Ruby MESI_Two_Level ignores clflush (same as InvisiSpec)",
    "gem5-recon-ruby3": "Ruby MESI_Three_Level ignores clflush (first access after it hits M in L0)",
    "gem5-spt": "panics: commit_impl.hh:1610 assertion srcRegTaintVec != nullptr at the clflush",
}


def check_build(strategy: str, gem5_bin: str) -> None:
    if strategy in ("full", "random_all"):
        fill_config()
        return
    if strategy in ("cold", "random"):
        for key, why in CLFLUSH_UNSUPPORTED.items():
            if key in str(gem5_bin):
                raise CacheSetupError(f"cache_setup={strategy} unsupported on {gem5_bin}: {why}")


def transform_asm(text: str, stem: str, strategy: str) -> Tuple[str, dict]:
    if strategy not in STRATEGIES:
        raise CacheSetupError(f"unknown cache_setup {strategy!r} (known: {', '.join(KNOWN)})")
    lines = text.split("\n")
    at = find_barrier(lines, stem)
    frame = frame_region(lines, stem, at)
    payload = STRATEGIES[strategy](frame)
    block = (["\t#APP",
              f"{BEGIN_LABEL}:"] + payload + [f"{END_LABEL}:", "\t#NO_APP"])
    new = lines[:at] + block + lines[at:]
    n_flush = sum(1 for p in payload if "clflush" in p)
    info = dict(strategy=strategy, frame=frame, n_clflush=n_flush,
                n_payload_instrs=sum(1 for p in payload if not
                                     p.strip().startswith(".") and
                                     not p.strip().endswith(":")))
    if strategy == "full":
        info.update(fill_config())
    return "\n".join(new), info


def _nm(binary: Path) -> Dict[str, int]:
    out = subprocess.check_output(["nm", "--defined-only", str(binary)], text=True)
    syms = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    return syms


def _rows(binary: Path) -> List[tuple]:
    out = subprocess.check_output(["objdump", "-d", "--no-show-raw-insn", str(binary)],
                                  text=True, stderr=subprocess.DEVNULL)
    rows = []
    for line in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        ops = m.group(3)
        t = re.match(r"([0-9a-f]+) <[^>]*>", ops)
        tgt = int(t.group(1), 16) if t else None
        ops = re.sub(r"\s*#.*$", "", ops) if t is None else ""
        rows.append((int(m.group(1), 16), m.group(2), ops.strip(), tgt))
    return rows


def _set_path(obj, path: str, value):
    toks = re.findall(r"\.([^.\[]+)|\[(\d+)\]", path)
    cur = obj
    for k, i in toks[:-1]:
        cur = cur[k] if k else cur[int(i)]
    k, i = toks[-1]
    if k:
        cur[k] = value
    else:
        cur[int(i)] = value
    return cur, (k if k else None)


def remap_annotation(ann: dict, old_bin: Path, new_bin: Path, stem: str) -> Tuple[dict, dict]:
    so, sn = _nm(old_bin), _nm(new_bin)
    if BEGIN_LABEL not in sn or END_LABEL not in sn:
        raise CacheSetupError("insertion labels missing from the new binary")
    begin, end = sn[BEGIN_LABEL], sn[END_LABEL]
    delta = end - begin
    ro, rn = _rows(old_bin), _rows(new_bin)
    pre_o = [r for r in ro if r[0] < begin]
    pre_n = [r for r in rn if r[0] < begin]
    mid = [r for r in rn if begin <= r[0] < end]
    post_o = [r for r in ro if r[0] >= begin]
    post_n = [r for r in rn if r[0] >= end]
    shift = lambda a: a + delta if a >= begin else a
    if pre_o != pre_n:
        raise CacheSetupError("code before the insertion point changed")
    if len(post_o) != len(post_n):
        raise CacheSetupError("instruction count after the insertion point changed")
    for a, b in zip(post_o, post_n):
        if (b[0], b[1], b[2]) != (a[0] + delta, a[1], a[2]) or \
           (a[3] is not None and b[3] != shift(a[3])):
            raise CacheSetupError(f"non-constant shift at {a[0]:#x}: {a} -> {b}")
    lab_o = {k: v for k, v in so.items() if k.startswith(f"__litmus_{_safe(stem)}_")}
    lab_n = {k: v for k, v in sn.items() if k.startswith(f"__litmus_{_safe(stem)}_")}
    if set(lab_o) != set(lab_n) or any(lab_n[k] != shift(v) for k, v in lab_o.items()):
        raise CacheSetupError("a __litmus_ label did not move by the insertion length")
    if so.get(stem) != sn.get(stem):
        raise CacheSetupError("function base changed")
    starts = {r[0] for r in ro}
    new = json.loads(json.dumps(ann))
    fields = addr_fields(ann)
    moved = 0
    for path, v in fields.items():
        if path == ".func_base_addr":
            continue
        if v >= begin:
            if v not in starts:
                raise CacheSetupError(f"{path}={v:#x} is not an instruction start")
            nv = v + delta
            parent, key = _set_path(new, path, nv)
            hk = "addr_hex" if key == "addr" else f"{key}_hex"
            if isinstance(parent, dict) and hk in parent:
                parent[hk] = hex(nv)
            moved += 1
    for k in ("x86_offset",):
        if k in json.dumps(ann):
            raise CacheSetupError("legacy x86_offset annotations are not supported")
    if key_paths(new) != key_paths(ann):
        raise CacheSetupError("annotation field set changed")
    rn_by = {r[0]: r for r in rn}
    ro_by = {r[0]: r for r in ro}
    nf = addr_fields(new)
    for path, v in fields.items():
        a, b = ro_by.get(v), rn_by.get(nf[path])
        if path == ".func_base_addr":
            continue
        if a is None or b is None or (a[1], a[2]) != (b[1], b[2]):
            raise CacheSetupError(f"{path}: instruction differs after remap ({a} vs {b})")
    return new, dict(begin=hex(begin), delta=delta, n_addr_fields=len(fields) - 1,
                     n_moved=moved, n_labels=len(lab_o))


def prepare(s_path: Path, ann_path: Path, workdir: Path, build_fn,
            strategy: Optional[str] = None):
    strategy = strategy or current()
    if strategy in META:
        raise CacheSetupError(f"prepare() needs a concrete strategy, got {strategy!r}")
    if strategy == "warm":
        if current() == "warm":
            return build_fn(s_path, workdir), ann_path, None
        return build_fn(s_path, workdir, cache_setup_ok=True), ann_path, None
    stem = s_path.stem
    text = s_path.read_text()
    new_text, info = transform_asm(text, stem, strategy)
    ref_dir = workdir / "_cache_setup_warm_ref"
    ref_dir.mkdir(exist_ok=True)
    old_bin = build_fn(s_path, ref_dir, cache_setup_ok=True)
    cs_dir = workdir / "_cache_setup_src"
    cs_dir.mkdir(exist_ok=True)
    cs_s = cs_dir / s_path.name
    cs_s.write_text(new_text)
    new_bin = build_fn(cs_s, workdir, cache_setup_ok=True)
    ann = json.loads(Path(ann_path).read_text())
    new_ann, rep = remap_annotation(ann, old_bin, new_bin, stem)
    info.update(rep)
    out = workdir / f"{stem}.cache_setup.ann.json"
    out.write_text(json.dumps(new_ann, indent=2) + "\n")
    return new_bin, out, info


