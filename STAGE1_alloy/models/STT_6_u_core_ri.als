sig rBool {}
sig cBool {}
sig tBool {}

abstract sig State {}
sig Mem_s extends State {}
sig Reg_s extends State {}

abstract sig InstrType {}
one sig TLoad    extends InstrType {}
one sig TStore   extends InstrType {}
one sig TBranchn extends InstrType {}
one sig TBranchx extends InstrType {}
one sig TOthern  extends InstrType {}
one sig TOtherx  extends InstrType {}

sig Instruction {
	kind: one InstrType,

	spo: lone Instruction,

	inreg: set Inreg,
	inaddr: set Inaddr,
	outreg: set Outreg,
	inmem: set Inmem,
	outmem: set Outmem,

	isresolved: lone rBool,
	iscommitted: lone cBool,
	isxm: lone tBool,
}

fun committed : Instruction {iscommitted.cBool}
fun resolved : Instruction {isresolved.rBool}
fun xm : Instruction {isxm.tBool}

fun Loads    : Instruction { kind.TLoad    }
fun Stores   : Instruction { kind.TStore   }
fun Branchns : Instruction { kind.TBranchn }
fun Branchxs : Instruction { kind.TBranchx }
fun Otherns  : Instruction { kind.TOthern  }
fun Otherxs  : Instruction { kind.TOtherx  }

abstract sig Operand {
	opstate: one State,
	rf: set Operand,
	ddi: set Operand,
}

sig Inreg extends Operand {}
sig Inaddr extends Operand {}
sig Inmem extends Operand {}
sig Outreg extends Operand {}
sig Outmem extends Operand {}

fun ins : Instruction -> Operand {inreg+inmem+inaddr}
fun outs : Instruction -> Operand {outreg+outmem}
fun operands : Instruction -> Operand {ins+outs}

fact no_extra_ops {no (Operand - Instruction.operands)}

fact no_extra_State {no State - Operand.opstate}

fact limited_instr_per_op {all o: Operand | #(o.(~operands)) = 1}

fact ir_s {no (Inreg.opstate & Mem_s)}
fact ia_s {no (Inaddr.opstate & Mem_s)}
fact im_s {no (Inmem.opstate & Reg_s)}
fact or_s {no (Outreg.opstate & Mem_s)}
fact om_s {no (Outmem.opstate & Reg_s)}

fact ld_ops   {no Loads.(inreg+outmem)}
fact str_ops  {no Stores.(inmem+outreg)}
fact other_ops {no (Otherns+Otherxs).(inaddr+inmem+outmem)}
fact br_ops   {no (Branchns+Branchxs).(inaddr+inmem+outmem+outreg)}

fact limited_inregs {all i: Instruction | #(i.inreg) <= 2}
fact limited_inaddrs {all i: Instruction | #(i.inaddr) <= 1}
fact limited_inmems {all i: Instruction | #(i.inmem) <= 1}
fact limited_ins {all i: Instruction | #(i.ins) <= 2}
fact limited_outs {all i: Instruction | #(i.(outreg+outmem)) <= 1}

fact spo_acyclic { acyclic[spo] }
fact spo_prior { all i: Instruction | lone i.(~spo) }
fact spo_total { total[spo, Instruction] }

fact committed_resolved {committed in resolved}
fun uncommitted : Instruction {Instruction - committed}
fun unresolved : Instruction {Instruction - resolved}
fact committed_last {no ^(spo :>uncommitted).^(spo :> committed) and (no uncommitted <: ^spo :> committed)}
fun last_committed : Instruction {(committed <: spo :> uncommitted).uncommitted}
fun first_uncommitted : Instruction {(some committed) => committed.(committed <: spo :> uncommitted) else first_instr}

fun no_unresolved_brs : Instruction {
	Instruction - (uncommitted & (Branchxs+Branchns)).(^(spo))
}
fun no_unresolved_mem : Instruction {
	Instruction - (uncommitted & (Loads+Stores)).(^(spo))
}

fun first_instr : Instruction {Instruction - Instruction.spo}

fact constrainddi {no ddi - (~ins).outs}
fact constrainrf {rf in (Instruction.outs -> Instruction.ins)}
fact one_entering_rf {all o: Operand | lone rf.o}
fact unidirectional_rf {acyclic[(operands).rf.(~operands) + spo]}
fact same_state_rf {no ((~opstate).rf.opstate - iden)}

fact rf_from_most_recent_writer {
  all prod: Instruction.outs, use: prod.rf |
    no other: (Instruction.outs - prod) |
        other.opstate = prod.opstate
        and (prod.(~operands))  -> (other.(~operands)) in ^spo
        and (other.(~operands)) -> (use.(~operands))   in ^spo
}

fact ld_ddi    {no (Loads.operands <: ddi) - (Inmem->Outreg)}
fact str_ddi   {no (Stores.operands <: ddi) - (Inreg->Outmem)}
fact other_ddi {no ((Otherns+Otherxs).operands <: ddi) - (Inreg->Outreg)}
fact br_ddi    {no ((Branchxs+Branchns).operands <: ddi)}

pred irreflexive[rel: Instruction->Instruction]       { no iden & rel }
pred acyclic[rel: Instruction->Instruction]           { irreflexive[^rel] }
pred total[rel: Instruction->Instruction, bag: Instruction] {
  all disj e0, e1: bag | e0->e1 in ^rel + ~(^rel)
  acyclic[rel]
}

abstract sig PTag {}
one sig RO extends PTag {}
one sig RC extends PTag {}
one sig RR extends PTag {}
one sig RI extends PTag {}
one sig RS extends PTag {}
fun no_p : PTag->univ {
  (PTag->univ) - (PTag->univ)
}

fun committed_p[p: PTag->univ] : Instruction {committed + p[RC] - p[RI]}
fun uncommitted_p[p: PTag->univ] : Instruction {uncommitted - p[RC] - p[RI]}
fun resolved_p[p: PTag->univ] : Instruction {resolved + p[RR] - p[RI]}
fun unresolved_p[p: PTag->univ] : Instruction {unresolved - p[RR] - p[RI]}
fun last_committed_p[p: PTag->univ] : Instruction { ((committed_p[p]) <: spo :> (uncommitted_p[p])).(uncommitted_p[p])}
fun first_uncommitted_p[p: PTag->univ] : Instruction {committed_p[p].(committed_p[p] <: spo :> uncommitted_p[p])}

fact committed_in_resolved {no (unresolved & committed)}

fun i_p[p: PTag->univ] : Instruction {Instruction - p[RI]}
fun o_p[p: PTag->univ] : Operand {i_p[p].operands :> (Operand - p[RO] - opstate.(p[RS]))}

fun spo_p[p : PTag->univ] : Instruction->Instruction {spo.(iden :> (p[RI])).spo + (i_p[p] <: spo :> i_p[p])}

fun fix_rf_hole_p[p : PTag->univ] : Operand -> Operand {(opstate.Reg_s<:(rf.(ddi:>(p[RI].operands)).rf):>opstate.Reg_s) + (opstate.Mem_s<:(rf.(ddi:>(p[RI].operands)).rf):>opstate.Mem_s)}

fun rf_p[p : PTag->univ] : Operand -> Operand {o_p[p]<:rf:>o_p[p] + fix_rf_hole_p[p]}
fun ddi_p[p : PTag->univ] : Operand -> Operand {o_p[p]<:ddi:>o_p[p]}

fun op_edges_p[p: PTag->univ] : Operand -> Operand {rf_p[p] + ddi_p[p]}

fun f[p: PTag->univ] : Instruction {(i_p[p]) - (i_p[p]).(spo_p[p])}

fun leakage_function_p[p: PTag->univ] : Operand {leakage_function & o_p[p]}

fun speculative_xmit_p[p: PTag->univ] : Operand {leakage_function_p[p] <: speculation_contract_p[p].operands}

fun a[p:PTag->univ,i:Instruction,o:Operand] : Operand { prot_set_propagation_p[p,i,o]}
fun last_committed_protset_p[p: PTag->univ] : Operand {
		a[p,f[p].(spo_p[p]).(spo_p[p]).(spo_p[p]).(spo_p[p]).(spo_p[p]).(spo_p[p]),
a[p,f[p].(spo_p[p]).(spo_p[p]).(spo_p[p]).(spo_p[p]).(spo_p[p]),
a[p,f[p].(spo_p[p]).(spo_p[p]).(spo_p[p]).(spo_p[p]),
a[p,f[p].(spo_p[p]).(spo_p[p]).(spo_p[p]),
a[p,f[p].(spo_p[p]).(spo_p[p]),
			a[p,f[p].(spo_p[p]),
				a[p,f[p],hardware_protection_policy[p]]
			]
	]
]]]]
}

fun has_unresolved_brs_p[p: PTag->univ] : Instruction {
	((unresolved_p[p] & (Branchxs+Branchns)).(^(spo_p[p])))
}
fun no_unresolved_brs_p[p: PTag->univ] : Instruction {
	i_p[p] - has_unresolved_brs_p[p]
}

fun no_unresolved_brs_bf_or_is_p[p: PTag->univ] : Instruction {
	no_unresolved_brs_p[p] - (unresolved_p[p] & (Branchxs+Branchns))
}

fun no_unresolved_mem_p[p: PTag->univ] : Instruction {
	i_p[p] - (uncommitted & (Loads+Stores)).(^(spo))
}

pred secure_speculation_scheme_p[p: PTag->univ] {
	(no (last_committed_protset_p[p] & speculative_xmit_p[p])) and
	(no last_committed_protset_p[p].(^(op_edges_p[p])) & speculative_xmit_p[p])
}

fact one_xm {#(xm) = 1}
fact tag_xm {
	(some (last_committed_protset_p[no_p] & speculative_xmit_p[no_p] & xm.operands)) or
	(some last_committed_protset_p[no_p].(^(op_edges_p[no_p])) & speculative_xmit_p[no_p] & xm.operands)
}

let gen_useful_litmus {
  not secure_speculation_scheme_p[no_p]

  all i: (unresolved - first_uncommitted) | secure_speculation_scheme_p[RR->i]
  secure_speculation_scheme_p[RC->first_uncommitted + RR->first_uncommitted]

  all s: State | secure_speculation_scheme_p[RS->s]

  all i: Instruction | secure_speculation_scheme_p[RI->i]
}

fact no_extra_inst {no ((Instruction-Branchns) - operands.Operand)}

run gen_lit {
  gen_useful_litmus
} for 9 but 6 Instruction, exactly 1 rBool, exactly 1 cBool, exactly 1 tBool

fun speculation_contract_p[p: PTag->univ] : Instruction {uncommitted_p[p] & has_unresolved_brs_p[p]}
fun u_store_shadow_p[p: PTag->univ] : Instruction {
	(unresolved_p[p] & Stores).(^(spo_p[p]))
}

fun hardware_protection_policy[p: PTag->univ]: Operand {(Loads & speculation_contract_p[p]).inmem & o_p[p]}
fun prot_set_propagation_p[p:PTag->univ,i:Instruction,o:Operand] : Operand { o }

fun leakage_function : Operand {Loads.inaddr+(Branchxs).inreg}
