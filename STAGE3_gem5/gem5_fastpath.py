from __future__ import annotations

import contextlib
import functools
import os
import sys
import threading
import time
import traceback

_GC = None
_ORIG = {}
_TLS = threading.local()
_HOOK_CACHE = {}
_HOOK_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()

MAX_TRACE_BYTES = int(float(os.environ.get("SIMSPECT_FAST_PATH_MAX_TRACE_MB", "512")) * 1024 * 1024)
_CHUNK = 16 * 1024 * 1024

LSQ_KEYS = ("system.cpu.iew.lsq", "system.cpu.dcache", "Initiating Translation inst [sn:")
COMMIT_KEY = "system.cpu.commit"
COMMIT_INST_KEY = "Committing instruction with [sn:"
COMMIT_SQUASH_KEY = "Squashing due to branch mispred PC:"

ROUTES = (("parse_pipeview", "o3pv"), ("parse_pipeview_by_seq", "o3pv"),
          ("parse_simspect_events", "simspect"), ("parse_lsq", "lsq"),
          ("parse_commit_ticks", "commit_inst"), ("parse_commit_squashes", "commit_squash"))


def _log(msg: str) -> None:
    path = os.environ.get("SIMSPECT_FAST_PATH_LOG")
    line = (f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] fastpath pid={os.getpid()} "
            f"tid={threading.get_ident()} {msg}\n")
    try:
        if path:
            with _LOG_LOCK, open(path, "a") as f:
                f.write(line)
        elif msg.startswith(("INSTALL", "ERROR")):
            sys.stderr.write(line)
    except Exception:
        pass


def _scan(path: str, marker: bytes) -> bool:
    keep = len(marker) - 1
    tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                return False
            buf = tail + chunk
            if marker in buf:
                return True
            tail = buf[-keep:] if keep else b""


def binary_has_resolve_hooks(gem5_bin) -> bool:
    try:
        p = os.path.realpath(str(gem5_bin))
        st = os.stat(p)
    except OSError:
        return _ORIG["binary_has_resolve_hooks"](gem5_bin)
    key = (p, st.st_size, st.st_mtime_ns, st.st_ino)
    with _HOOK_LOCK:
        if key in _HOOK_CACHE:
            return _HOOK_CACHE[key]
    t0 = time.monotonic()
    try:
        v = _scan(p, _GC._FORCE_MARKER)
    except OSError:
        v = False
    with _HOOK_LOCK:
        _HOOK_CACHE[key] = v
    _log(f"HOOKSCAN {p} size={st.st_size} mtime_ns={st.st_mtime_ns} hooks={v} "
         f"scan_s={time.monotonic() - t0:.3f} (cached for this process)")
    return v


def _ident(path):
    st = os.stat(path)
    return (st.st_size, st.st_mtime_ns, st.st_ino)


def _load(trace_path):
    cats = dict(o3pv=[], simspect=[], lsq=[], commit_inst=[], commit_squash=[])
    unglue = _GC._unglue
    sp = _GC.SIMSPECT_PREFIX
    o3, ss, lsq, ci, cs = (cats[k] for k in ("o3pv", "simspect", "lsq", "commit_inst", "commit_squash"))
    n = 0
    with open(trace_path) as f:
        for raw in f:
            n += 1
            line = unglue(raw)
            if line.startswith("O3PipeView:"):
                (ss if line.startswith(sp) else o3).append(line)
                continue
            if COMMIT_KEY in line:
                if COMMIT_INST_KEY in line:
                    ci.append(line)
                if COMMIT_SQUASH_KEY in line:
                    cs.append(line)
            if LSQ_KEYS[0] in line or LSQ_KEYS[1] in line or LSQ_KEYS[2] in line:
                lsq.append(line)
    cats["_n_lines"] = n
    return cats


def _routed(trace_path):
    st = _TLS
    if not getattr(st, "active", False):
        return None
    if getattr(st, "fallback", None):
        return None
    key_path = str(trace_path)
    try:
        ident = _ident(trace_path)
    except Exception:
        return None
    c = getattr(st, "cache", None)
    if c is not None and c["path"] == key_path and c["ident"] == ident:
        return c["cats"]
    if ident[0] > MAX_TRACE_BYTES:
        st.fallback = f"trace {ident[0] / 1048576:.1f} MB > SIMSPECT_FAST_PATH_MAX_TRACE_MB"
        return None
    t0 = time.monotonic()
    try:
        cats = _load(trace_path)
    except Exception as e:
        st.fallback = f"single read raised {type(e).__name__}: {str(e)[:200]}"
        return None
    if c is not None:
        st.reloads = getattr(st, "reloads", 0) + 1
    st.cache = dict(path=key_path, ident=ident, cats=cats)
    st.read_s = getattr(st, "read_s", 0.0) + (time.monotonic() - t0)
    st.trace_bytes = ident[0]
    return cats


def _set_class(lines, path):
    prev = (getattr(_TLS, "cls", None), getattr(_TLS, "cls_path", None))
    _TLS.cls, _TLS.cls_path = lines, path
    return prev


def _wrap_parser(name, cls):
    orig = _ORIG[name]

    @functools.wraps(orig)
    def wrapper(trace_path, *a, **kw):
        cats = _routed(trace_path)
        if cats is None:
            return orig(trace_path, *a, **kw)
        prev = _set_class(cats[cls], str(trace_path))
        try:
            return orig(trace_path, *a, **kw)
        finally:
            _TLS.cls, _TLS.cls_path = prev
    wrapper._fastpath_wrapped = True
    return wrapper


def _trace_lines(trace_path):
    lines = getattr(_TLS, "cls", None)
    if lines is not None and getattr(_TLS, "cls_path", None) == str(trace_path):
        return iter(lines)
    return _ORIG["_trace_lines"](trace_path)


_SCOPE_KEYS = ("active", "cache", "fallback", "cls", "cls_path", "read_s", "trace_bytes", "reloads")


@contextlib.contextmanager
def routed_scope():
    st = _TLS
    saved = {k: getattr(st, k, None) for k in _SCOPE_KEYS}
    st.active, st.cache, st.fallback, st.cls, st.cls_path = True, None, None, None, None
    st.read_s, st.trace_bytes, st.reloads = 0.0, None, 0

    def describe():
        c = st.cache
        if st.fallback:
            return f"production reason=\"{st.fallback}\""
        if c is None:
            return "production reason=\"no trace parsed (no gem5 run or it failed)\""
        cats = c["cats"]
        return (f"fast trace_mb={st.trace_bytes / 1048576:.2f} lines={cats['_n_lines']} "
                f"o3pv={len(cats['o3pv'])} simspect={len(cats['simspect'])} lsq={len(cats['lsq'])} "
                f"commit_inst={len(cats['commit_inst'])} commit_squash={len(cats['commit_squash'])} "
                f"read_s={st.read_s:.3f} reloads={st.reloads}")
    try:
        yield describe
    finally:
        for k, v in saved.items():
            setattr(st, k, v)


def process_one(s_path, ann_path, check_fn, keep_tmp: bool = False):
    t0 = time.monotonic()
    res = None
    with routed_scope() as describe:
        try:
            res = _ORIG["process_one"](s_path, ann_path, check_fn, keep_tmp)
            return res
        finally:
            try:
                r = res or {}
                _log(f"TEST {getattr(s_path, 'stem', s_path)} path={describe()} status={r.get('status')} "
                     f"iiw={r.get('issued_in_window')} wall_s={time.monotonic() - t0:.2f}")
            except Exception:
                _log(f"ERROR logging test {s_path}:\n{traceback.format_exc()}")


def install(gc) -> None:
    global _GC
    if getattr(gc, "_FASTPATH_INSTALLED", False):
        return
    _GC = gc
    for name in ("_trace_lines", "binary_has_resolve_hooks", "process_one") + tuple(n for n, _ in ROUTES):
        _ORIG[name] = getattr(gc, name)
    for name, cls in ROUTES:
        setattr(gc, name, _wrap_parser(name, cls))
    gc._trace_lines = _trace_lines
    gc.binary_has_resolve_hooks = binary_has_resolve_hooks
    gc.process_one = process_one
    gc._FASTPATH_INSTALLED = True
    _log(f"INSTALL gem5_common={getattr(gc, '__file__', '?')} gem5_bin={getattr(gc, 'GEM5_BIN', '?')} "
         f"max_trace_mb={MAX_TRACE_BYTES // 1048576} python={sys.version.split()[0]} "
         f"(hook-scan cache + routed trace read inside process_one; records identical by construction)")
