
from gem5_common import best_record, check_branch_resolutions, run_batch

_STAGES = ("fetch", "decode", "rename", "dispatch", "issue", "complete", "retire")


def _last_alive_tick(rec):
    if rec is None:
        return 0
    for stage in reversed(_STAGES):
        if rec[stage] > 0:
            return rec[stage]
    return 0


def check_br(by_pc, xmit_pc, lc_pc, fnc_pc, unresolved, ticks_per_cycle, lsq_by_pc=None, squash_by_pc=None):
    xmit_rec = best_record(by_pc.get(xmit_pc, []))
    lc_rec   = best_record(by_pc.get(lc_pc,   [])) if lc_pc  else None
    fnc_rec  = best_record(by_pc.get(fnc_pc,  [])) if fnc_pc else None

    ft_pc  = None
    ft_rec = None
    for pc in sorted(by_pc.keys()):
        if pc > xmit_pc:
            ft_pc  = pc
            ft_rec = best_record(by_pc[pc])
            break

    xmit_last_alive = _last_alive_tick(xmit_rec)
    ft_last_alive   = _last_alive_tick(ft_rec)
    xmit_complete   = xmit_rec.get("complete", 0) if xmit_rec else 0

    commit_traced = bool(squash_by_pc)
    xmit_squashes = squash_by_pc.get(xmit_pc, []) if squash_by_pc else []
    if commit_traced:
        xmit_redirect = xmit_squashes[0] if xmit_squashes else 0
        xmit_signal   = xmit_redirect
        branch_redirected = (xmit_redirect > 0
                             and (ft_rec is None or ft_rec.get("retire", 0) == 0))
    else:
        xmit_redirect = 0
        xmit_signal   = xmit_complete
        branch_redirected = (
            ft_rec is not None
            and xmit_rec is not None
            and xmit_complete > 0
            and ft_rec.get("retire", 0) == 0
        )

    lc_retire     = lc_rec["retire"]  if lc_rec  else 0
    fnc_retire    = fnc_rec["retire"] if fnc_rec else 0
    fnc_complete  = fnc_rec["complete"] if fnc_rec else 0

    lc_unretired_but_specified = (lc_pc is not None) and (lc_retire == 0)
    disqualified = lc_unretired_but_specified

    after_lc   = (lc_retire == 0)  or (xmit_signal > lc_retire)
    before_fnc = (fnc_retire == 0) or (xmit_signal < fnc_retire)

    branches_unresolved, branch_details = check_branch_resolutions(
        by_pc, xmit_signal, unresolved, ticks_per_cycle)

    issued_in_window = (not disqualified
                        and branch_redirected
                        and (xmit_signal > 0) and after_lc and before_fnc
                        and branches_unresolved)

    criteria = dict(
        lc_retired=not disqualified,
        signal_seen=xmit_signal > 0,
        branch_redirected=branch_redirected,
        after_lc=after_lc,
        before_fnc=before_fnc,
        branches_unresolved=branches_unresolved,
    )

    return dict(
        issued_in_window=issued_in_window,
        criteria=criteria,
        xmit_signal=xmit_signal,
        xmit_complete=xmit_complete,
        xmit_redirect=xmit_redirect,
        xmit_last_alive=xmit_last_alive,
        ft_last_alive=ft_last_alive,
        ft_pc=hex(ft_pc) if ft_pc else None,
        lc_retire=lc_retire,
        lc_unretired_but_specified=lc_unretired_but_specified,
        fnc_retire=fnc_retire,
        fnc_complete=fnc_complete,
        branches_unresolved=branches_unresolved,
        branch_resolutions=branch_details,
    )


if __name__ == "__main__":
    run_batch(check_br, description="branch transmitter: xmit outlives fall-through")
