#include "cpu/o3/secure_scheme/taint_tracker.hh"

#include "cpu/inst_seq.hh"
#include "cpu/o3/dyn_inst.hh"
#include "params/BaseO3CPU.hh"

namespace gem5
{



namespace o3
{

TaintTracker::TaintTracker(CPU *_cpu, const BaseO3CPUParams &params)
    : _cpu(_cpu),
      stats(_cpu)
{

}

TaintTracker::TaintTrackerStats::TaintTrackerStats(CPU *cpu)
    : statistics::Group(cpu, "taint_tracker"),
    ADD_STAT(insertedTaintInsts, statistics::units::Count::get(),
            "Number of tainting instructions inserted into taint tracker"),
    ADD_STAT(insertedTaints, statistics::units::Count::get(),
            "Number of taints inserted into taint tracker"),
    ADD_STAT(freedTaints, statistics::units::Count::get(),
            "Number of taints freed from taint tracker"),
    ADD_STAT(allowlistedTaintsFromTT, statistics::units::Count::get(),
            "Number of taints untainted because they were safe")
{
    insertedTaints.prereq(insertedTaints);
    freedTaints.prereq(freedTaints);
}

void
TaintTracker::resetState()
{
    taints.clear();
}

void
TaintTracker::insertTaintInst(const DynInstPtr &load_inst)
{
    assert(load_inst->isLoad());
    for (int i = 0; i < load_inst->numDestRegs(); i++) {
        ++stats.insertedTaintInsts;;

        PhysRegIdPtr regId = load_inst->renamedDestIdx(i);
        insertTaint(regId, load_inst);
    }
}

void
TaintTracker::insertTaint(const PhysRegIdPtr &regId,
                          const DynInstPtr &load_inst)
{
    if (regId->flatIndex() == 16) return;
    if (regId->is(RegClassType::InvalidRegClass)) return;

    ++stats.insertedTaints;

    taints.insert(std::make_pair(regId, load_inst));
}

bool
TaintTracker::isTaintedInst(const DynInstPtr &load_inst)
{
    for (int i = 0; i < load_inst->numSrcRegs(); i++) {
        if (isTainted(load_inst->renamedSrcIdx(i)))
            return true;
    }
    return false;
}

bool
TaintTracker::isTainted(const PhysRegIdPtr &regId)
{
    auto it = taints.find(regId);
    return it != taints.end();
}

bool
TaintTracker::hasTaintedSrc(const DynInstPtr &inst)
{
    for (int src_reg_idx = 0;
         src_reg_idx < inst->numSrcRegs();
         src_reg_idx ++)
    {
        PhysRegIdPtr regId = inst->renamedSrcIdx(src_reg_idx);
        if (isTainted(regId)) {
            return true;
        }
    }
    return false;
}

DynInstPtr
TaintTracker::getTaintSource(const PhysRegIdPtr &regId)
{
    auto it = taints.find(regId);
    assert (it != taints.end());
    return it->second;
}

void
TaintTracker::propagateTaints(const DynInstPtr &inst)
{
    if (!hasTaintedSrc(inst)) return;
    const DynInstPtr oldest = getOldestTaint(inst);
    for (int i = 0; i < inst->numDestRegs(); i++) {
        insertTaint(inst->renamedDestIdx(i), oldest);
    }

}

DynInstPtr
TaintTracker::getOldestTaint(const DynInstPtr &inst)
{
    DynInstPtr oldest = inst;
    for (int i = 0; i < inst->numSrcRegs(); i++) {
        PhysRegIdPtr reg = inst->renamedSrcIdx(i);
        if (isTainted(reg) &&
            taints.at(reg)->seqNum < oldest->seqNum) {
            oldest = taints.at(reg);
        }
    }
    assert(oldest->seqNum < inst->seqNum);
    return oldest;
}

void
TaintTracker::freeTaints()
{
    for (auto it = taints.cbegin(); it != taints.cend(); ) {
        DynInstPtr inst = it->second;
        if (!inst->isSpeculative()) {
//        if (inst->nowVisible || inst->isSquashed()) {
            taints.erase(it++);
        }
        else if(_cpu->allowLeaked){
          if(inst->revealBit && !isTaintedInst(inst) && !inst->stlForw && inst->loadCompleted){
            taints.erase(it++);
            stats.allowlistedTaintsFromTT++;
          }
          else {
            ++it;
          }
        } 
        else{
            ++it;
        }
    }
}

void
TaintTracker::updateRevealedTaints(unsigned long int Addr){
    for (auto it = taints.cbegin(); it != taints.cend(); ) {
        DynInstPtr inst = it->second;
        if(inst->physEffAddr == Addr
              && !isTaintedInst(inst) && !inst->stlForw){
            taints.erase(it++);
            stats.allowlistedTaintsFromTT++;
        }
        else{
          ++it;
        }
    }
}

void
TaintTracker::cleanTaints()
{
    for (auto it = taints.cbegin(); it != taints.cend(); ) {
        DynInstPtr inst = it->second;
        if (inst->isSquashed() || inst->isCommitted()) {
            taints.erase(it++);
        } else {
            ++it;
        }
    }
}

void
TaintTracker::sanityCheck()
{
    assert(taints.size() < 1000);
}

void
TaintTracker::squashFromInst(InstSeqNum squash_num)
{
    for (auto it = taints.cbegin(); it != taints.cend(); ) {
        DynInstPtr inst = it->second;
        if (inst->seqNum > squash_num) {
            taints.erase(it++);
        } else {
            ++it;
        }
    }
}

void
TaintTracker::tick()
{
    cleanTaints();
    freeTaints();
    sanityCheck();
}


} // namespace o3
} // namespace gem5
