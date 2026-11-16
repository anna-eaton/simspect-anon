import sys

src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()


def rep(old, new):
    global s
    n = s.count(old)
    assert n == 1, f"expected 1 occurrence, found {n}: {old!r}"
    s = s.replace(old, new)


rep("isa_spec = '/code/revizor-docker/src/x86/isa_spec/base.json'",
    "isa_spec = os.path.join(os.getcwd(), 'x86/isa_spec/base.json')")

T5_HELPERS = r'''
import json as _t5json
import resource as _t5res
_T5 = {}
_T5_START = [None]
_T5_LAST_SAMPLE = [0.0]
_T5_TCK = os.sysconf('SC_CLK_TCK')

def _t5_pg_cpu(pgid):
    tot = 0
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        try:
            with open(f'/proc/{d}/stat') as f:
                st = f.read()
        except OSError:
            continue
        fields = st[st.rfind(')') + 2:].split()
        if int(fields[2]) != pgid:
            continue
        tot += sum(int(x) for x in fields[11:15])
    return tot / _T5_TCK

def _t5_dump():
    out = {'start_time': _T5_START[0], 'instances': [_T5[k] for k in sorted(_T5)]}
    tmp = f'{args.output}/t5_instances.json.tmp'
    with open(tmp, 'w') as f:
        _t5json.dump(out, f, indent=1)
    os.replace(tmp, f'{args.output}/t5_instances.json')

def _t5_rec(index, round):
    if round not in _T5:
        _T5[round] = {'round': round, 'pid': processes[index].pid if processes[index] else None,
                      'events': [], 'cpu_sample': None, 'progress_sample': None,
                      'wall_sample': None, 'exit': None}
    return _T5[round]

def _t5_track(index, round, stdout):
    rec = _t5_rec(index, round)
    v = get_violation_count(stdout) or 0
    last = rec['events'][-1]['viol'] if rec['events'] else 0
    if v > last:
        rec['events'].append({'viol': v, 'progress': get_case_count(stdout),
                              'wall': time.time() - _T5_START[0],
                              'cpu': _t5_pg_cpu(rec['pid'])})
        _t5_dump()

def _t5_sample_all():
    now = time.time()
    if now - _T5_LAST_SAMPLE[0] < 20:
        return
    _T5_LAST_SAMPLE[0] = now
    for index, p in enumerate(processes):
        if p is None:
            continue
        round = index // len(configs)
        rec = _t5_rec(index, round)
        rec['cpu_sample'] = _t5_pg_cpu(p.pid)
        rec['wall_sample'] = now - _T5_START[0]
        rec['progress_sample'] = get_case_count(results[index % len(configs)][round].stdout)
    _t5_dump()

def _t5_reap(index, round):
    p = processes[index]
    rec = _t5_rec(index, round)
    try:
        _pid, status, ru = os.wait4(p.pid, 0)
        p.returncode = os.waitstatus_to_exitcode(status)
        rec['exit'] = {'returncode': p.returncode, 'wall': time.time() - _T5_START[0],
                       'rusage_cpu': ru.ru_utime + ru.ru_stime,
                       'cpu_sample_before_exit': rec['cpu_sample']}
    except ChildProcessError as e:
        rec['exit'] = {'error': repr(e), 'wall': time.time() - _T5_START[0]}
    _t5_dump()
'''

rep("def main():\n", T5_HELPERS + "\ndef main():\n")

rep("    start_time = time.time()\n    selector = selectors.DefaultSelector()\n",
    "    start_time = time.time()\n    _T5_START[0] = start_time\n    selector = selectors.DefaultSelector()\n")

rep("            if result.first_violation is None and get_violation_count(stdout):\n",
    "            _t5_track(index, round, stdout)\n"
    "            if result.first_violation is None and get_violation_count(stdout):\n")

rep("                selector.unregister(key.fileobj)\n                processes[index].wait()\n",
    "                selector.unregister(key.fileobj)\n                _t5_reap(index, round)\n                processes[index].wait()\n")

rep("        if all(process is None for process in processes):\n            break\n",
    "        _t5_sample_all()\n        if all(process is None for process in processes):\n            break\n")

rep("    end_time = time.time()\n",
    "    end_time = time.time()\n"
    "    _ru = _t5res.getrusage(_t5res.RUSAGE_CHILDREN)\n"
    "    with open(f'{args.output}/t5_rusage_children.json', 'w') as _f:\n"
    "        _t5json.dump({'wall': end_time - start_time, 'cpu_user': _ru.ru_utime, 'cpu_sys': _ru.ru_stime,\n"
    "                      'cpu_total': _ru.ru_utime + _ru.ru_stime, 'maxrss_kb': _ru.ru_maxrss}, _f, indent=1)\n"
    "    _t5_dump()\n")

open(dst, 'w').write(s)
print('wrote', dst)
