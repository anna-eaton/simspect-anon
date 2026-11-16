
from gem5_common import best_record, check_branch_resolutions, run_batch


def _xmit_execute_tick(lsq_by_pc, xmit_pc):
    if not lsq_by_pc:
        return 0
    recs = lsq_by_pc.get(xmit_pc, [])
    return max((r.get("execute_tick", 0) for r in recs), default=0)


def _xmit_cache_fate(lsq_by_pc, xmit_pc):
    recs = (lsq_by_pc or {}).get(xmit_pc, [])
    if not recs:
        return None
    executed = [r for r in recs if r.get("execute_tick", 0) > 0]
    if not executed:
        return dict(cache_fate="never_executed", real_access=False,
                    packet_tick=0, spec_read_tick=0, load_squash_tick=0)
    reached = [r for r in executed if r.get("packet_tick", 0) > 0]
    if reached:
        r = min(reached, key=lambda r: r["packet_tick"])
        return dict(cache_fate="reached_cache", real_access=True,
                    packet_tick=r["packet_tick"], spec_read_tick=0,
                    load_squash_tick=r.get("squash_tick", 0))
    specd = [r for r in executed if r.get("spec_read_tick", 0) > 0]
    if specd:
        r = min(specd, key=lambda r: r["spec_read_tick"])
        return dict(cache_fate="spec_read_only", real_access=False,
                    packet_tick=0, spec_read_tick=r["spec_read_tick"],
                    load_squash_tick=r.get("squash_tick", 0))
    r = executed[0]
    return dict(cache_fate="executed_no_packet", real_access=False,
                packet_tick=0, spec_read_tick=0,
                load_squash_tick=r.get("squash_tick", 0))


def check_ld(by_pc, xmit_pc, lc_pc, fnc_pc, unresolved, ticks_per_cycle, lsq_by_pc=None, squash_by_pc=None):
    xmit_rec = best_record(by_pc.get(xmit_pc, []))
    lc_rec   = best_record(by_pc.get(lc_pc,   [])) if lc_pc  else None
    fnc_rec  = best_record(by_pc.get(fnc_pc,  [])) if fnc_pc else None

    xmit_execute  = _xmit_execute_tick(lsq_by_pc, xmit_pc)
    xmit_complete = xmit_rec["complete"] if xmit_rec else 0
    xmit_signal   = xmit_execute if xmit_execute > 0 else xmit_complete

    xmit_issue   = xmit_rec["issue"]   if xmit_rec else 0
    xmit_retire  = xmit_rec["retire"]  if xmit_rec else 0
    lc_retire    = lc_rec["retire"]    if lc_rec   else 0
    fnc_retire   = fnc_rec["retire"]   if fnc_rec  else 0
    fnc_complete = fnc_rec["complete"] if fnc_rec  else 0

    lc_unretired_but_specified = (lc_pc is not None) and (lc_retire == 0)
    disqualified = lc_unretired_but_specified

    xmit_retired_in_window = xmit_retire > 0

    after_lc   = (lc_retire == 0) or (xmit_signal > lc_retire)
    before_fnc = (fnc_retire == 0) or (xmit_signal < fnc_retire)
    branches_unresolved, branch_details = check_branch_resolutions(
        by_pc, xmit_signal, unresolved, ticks_per_cycle)
    in_window = (not disqualified
                 and (xmit_signal > 0) and after_lc and before_fnc
                 and branches_unresolved)

    fate = _xmit_cache_fate(lsq_by_pc, xmit_pc)
    cache_fate = (fate or {}).get("cache_fate")
    if fate is None:
        data_obtained = None
    elif cache_fate == "reached_cache":
        data_obtained = True
    elif cache_fate == "spec_read_only":
        data_obtained = False
    elif cache_fate == "executed_no_packet":
        data_obtained = xmit_complete > 0
        if data_obtained:
            cache_fate = "store_forward"
    else:
        data_obtained = False

    gated = in_window and (xmit_execute > 0) and (data_obtained is not None)
    issued_in_window = (bool(data_obtained) if gated else in_window)

    criteria = dict(
        lc_retired=not disqualified,
        signal_seen=xmit_signal > 0,
        after_lc=after_lc,
        before_fnc=before_fnc,
        branches_unresolved=branches_unresolved,
        data_obtained=(bool(data_obtained)
                       if xmit_execute > 0 and data_obtained is not None else None),
    )

    return dict(
        issued_in_window=issued_in_window,
        in_window=in_window,
        criteria=criteria,
        data_obtained=data_obtained,
        cache_fate=cache_fate,
        real_access=(fate or {}).get("real_access"),
        packet_tick=(fate or {}).get("packet_tick"),
        spec_read_tick=(fate or {}).get("spec_read_tick"),
        load_squash_tick=(fate or {}).get("load_squash_tick"),
        xmit_signal=xmit_signal,
        xmit_execute=xmit_execute,
        xmit_complete=xmit_complete,
        xmit_issue=xmit_issue,
        xmit_retire=xmit_retire,
        xmit_retired_in_window=xmit_retired_in_window,
        lc_retire=lc_retire,
        lc_unretired_but_specified=lc_unretired_but_specified,
        fnc_retire=fnc_retire,
        fnc_complete=fnc_complete,
        branches_unresolved=branches_unresolved,
        branch_resolutions=branch_details,
    )


if __name__ == "__main__":
    run_batch(check_ld, description="load transmitter: xmit_complete in (lc_retire, fnc_retire)")
