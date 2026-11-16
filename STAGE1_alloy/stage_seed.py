import re
import sys
import argparse


def parse_txt(path):
    rels = {}
    pat = re.compile(r'this/([A-Za-z_]+(?:<:[A-Za-z_]+)?)=\{(.*)\}')
    with open(path) as f:
        for line in f:
            line = line.strip()
            m = pat.match(line)
            if not m:
                continue
            name, body = m.group(1), m.group(2)
            tuples = []
            if body.strip():
                for t in body.split(','):
                    tuples.append(tuple(x.strip() for x in t.split('->')))
            rels[name] = tuples
    return rels


def col(rels, name):
    return rels.get(name, [])


KIND_ATOM_TO_SIG = {
    'TLoad': 'Loads', 'TStore': 'Stores', 'TBranchn': 'Branchns',
    'TBranchx': 'Branchxs', 'TOthern': 'Otherns', 'TOtherx': 'Otherxs',
}


def build_pred(rels, pred_name):
    instrs = sorted({a for (a,) in col(rels, 'Instruction')},
                    key=lambda s: int(s.split('$')[1]))
    operands = sorted({a for (a,) in col(rels, 'Operand')},
                      key=lambda s: (s.split('$')[0], int(s.split('$')[1])))
    if not instrs:
        sys.exit(f"no instructions in core")

    ivar = {a: f"i{n}" for n, a in enumerate(instrs)}
    ovar = {a: f"o{n}" for n, a in enumerate(operands)}

    kind = {i: k for (i, k) in col(rels, 'Instruction<:kind')}
    spo = col(rels, 'Instruction<:spo')
    isres = {i for (i, _) in col(rels, 'Instruction<:isresolved')}
    iscom = {i for (i, _) in col(rels, 'Instruction<:iscommitted')}
    isxm = {i for (i, _) in col(rels, 'Instruction<:isxm')}

    slot_rels = ['inreg', 'inaddr', 'inmem', 'outreg', 'outmem']
    slots = {s: col(rels, f'Instruction<:{s}') for s in slot_rels}

    opstate = {o: st for (o, st) in col(rels, 'Operand<:opstate')}
    state_sig = lambda st: 'Reg_s' if st.startswith('Reg') else 'Mem_s'
    rf = col(rels, 'Operand<:rf')
    ddi = col(rels, 'Operand<:ddi')

    lines = []
    lines.append(f"pred {pred_name} {{")
    decl_i = ", ".join(ivar[i] for i in instrs)
    decl_o = ", ".join(ovar[o] for o in operands)
    decl = f"  some disj {decl_i}: Instruction"
    if operands:
        decl += f", disj {decl_o}: Operand"
    decl += " | {"
    lines.append(decl)

    for i in instrs:
        lines.append(f"    {ivar[i]} in {KIND_ATOM_TO_SIG[kind[i].split('$')[0]]}")
    for (a, b) in spo:
        lines.append(f"    {ivar[b]} in {ivar[a]}.^spo")
    for i in instrs:
        lines.append(f"    {ivar[i]} in resolved" if i in isres else f"    {ivar[i]} not in resolved")
    for i in instrs:
        lines.append(f"    {ivar[i]} in committed" if i in iscom else f"    {ivar[i]} not in committed")
    for i in instrs:
        if i in isxm:
            lines.append(f"    {ivar[i]} in xm")
    for s in slot_rels:
        for (i, o) in slots[s]:
            lines.append(f"    {ovar[o]} in {ivar[i]}.{s}")
    for o in operands:
        if o in opstate:
            lines.append(f"    {ovar[o]}.opstate in {state_sig(opstate[o])}")
    for (a, b) in rf:
        lines.append(f"    {ovar[b]} in {ovar[a]}.rf")
    for (a, b) in ddi:
        lines.append(f"    {ovar[b]} in {ovar[a]}.ddi")

    lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("core_txt")
    ap.add_argument("--pred-name", default="seed_core")
    args = ap.parse_args()
    rels = parse_txt(args.core_txt)
    print(build_pred(rels, args.pred_name))


if __name__ == "__main__":
    main()
