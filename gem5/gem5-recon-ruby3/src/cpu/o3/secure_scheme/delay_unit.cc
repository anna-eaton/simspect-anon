#include "cpu/o3/secure_scheme/delay_unit.hh"

#include "cpu/o3/dyn_inst.hh"
#include "debug/DelayDebug.hh"
#include "debug/DelayUnit.hh"

namespace gem5
{

namespace o3
{

DelayUnit::DelayUnit(CPU *_cpu, const BaseO3CPUParams &params)
    : cpu(_cpu),
      stats(cpu)
{

}

std::string
DelayUnit::name() const
{
    return cpu->name() + ".delay_unit";
}

DelayUnit::DelayUnitStats::DelayUnitStats(CPU *cpu)
    : statistics::Group(cpu, "delay_unit"),
        ADD_STAT(insertedTaintedLoads, statistics::units::Count::get(),
                "Number of tainted loads inserted into delay unit"),
        ADD_STAT(clearedTaintedLoads, statistics::units::Count::get(),
                "Number of tainted loads freed from delay unit"),
        ADD_STAT(squashedTaintedLoads, statistics::units::Count::get(),
                "Number of tainted loads squashed in delay unit"),
        ADD_STAT(insertedTaintedBranches, statistics::units::Count::get(),
                "Number of tainted branches inserted into delay unit"),
        ADD_STAT(clearedTaintedBranches, statistics::units::Count::get(),
                "Number of tainted branches freed from delay unit"),
        ADD_STAT(squashedTaintedBranches, statistics::units::Count::get(),
                "Number of tainted branched squashed in delay unit"),
        ADD_STAT(insertedDelayedMems, statistics::units::Count::get(),
                "Number of delayed mems inserted into delay unit"),
        ADD_STAT(clearedDelayedMems, statistics::units::Count::get(),
                "Number of delayed mems freed from delay unit"),
        ADD_STAT(squashedDelayedMems, statistics::units::Count::get(),
                "Number of delayed mems squashed in delay unit"),
        ADD_STAT(reissuedDelayedMems, statistics::units::Count::get(),
                "Delay-on-Miss loads that missed in the L1 Cache"),
        ADD_STAT(squashedFreedTaintedLoads, statistics::units::Count::get(),
                "Number of freed taints that were squashed (should be 0)"),
        ADD_STAT(allowlistedLoadsFromDU, statistics::units::Count::get(),
                "Number of allowd on delay unit because safe")
    {
    }

int
DelayUnit::getPosition(std::vector<DynInstPtr> &vec, InstSeqNum seqNum)
{
    int i = 0;
    for (; i < vec.size(); i++) {
        if (vec.at(i)->seqNum > seqNum)
            return i;
    }
    return i;
}

void
DelayUnit::insertTaintedLoad(const DynInstPtr &inst)
{
    assert(inst->isLoad());
    DPRINTF(DelayUnit, "Inserted tainted load [sn:%llu] into delay_unit\n",
            inst->seqNum);
    ++stats.insertedTaintedLoads;
    taintedLoads.insert(taintedLoads.begin() +
                            getPosition(taintedLoads, inst->seqNum),
                        inst);
}

void
DelayUnit::freeTaintedLoads()
{
    for (int i = 0; i < taintedLoads.size(); i++) {
        if (!cpu->taintTracker.isTaintedInst(taintedLoads.at(i))) {
            ++stats.clearedTaintedLoads;
            DPRINTF(DelayUnit, "Released tainted load [sn:%llu] from "
            "delay_unit as it is no longer tainted\n",
            taintedLoads.at(i)->seqNum);

            freedTaintedLoads.push_back(taintedLoads.at(i));
            taintedLoads.erase(taintedLoads.begin() + i);
            i--;
        }
    }
}

DynInstPtr
DelayUnit::getFreedTaintedLoad()
{
    assert(!freedTaintedLoads.empty());
    DynInstPtr inst = freedTaintedLoads.front();
    freedTaintedLoads.erase(freedTaintedLoads.begin());
    return inst;
}

bool
DelayUnit::hasFreedTaintedLoads()
{
    return !freedTaintedLoads.empty();
}

bool
DelayUnit::hasTaintedBranch(const DynInstPtr &inst)
{
    return std::find(taintedBranches.begin(),
                     taintedBranches.end(),
                     inst) != taintedBranches.end();
}

void
DelayUnit::insertTaintedBranch(const DynInstPtr &inst)
{
    assert(inst->isCondCtrl());
    DPRINTF(DelayUnit, "Inserting branch [sn:%llu] into delay_unit "
            "as it has tainted operands\n", inst->seqNum);

    ++stats.insertedTaintedBranches;

    taintedBranches.insert(taintedBranches.begin() +
                               getPosition(taintedBranches, inst->seqNum),
                           inst);
}

void
DelayUnit::freeTaintedBranches()
{
    if (taintedBranches.size() == 0) {
        return;
    }
    if (cpu->scheme == CPU::Scheme::DoM) {
        if (taintedBranches.at(0)->seqNum ==
            cpu->shadowTracker.getOldestBranchShadow()) {

            auto inst = std::move(taintedBranches.at(0));
            assert(inst);

            cpu->freeBranch(inst);
            taintedBranches.erase(taintedBranches.begin());
        }
        return;
    }
    for (int i = 0; i < taintedBranches.size(); i++) {
        if (!cpu->taintTracker.isTaintedInst(taintedBranches.at(i))) {
            ++stats.clearedTaintedBranches;
            DPRINTF(DelayUnit, "Released tainted branch [sn:%llu] from "
            "delay_unit as it is no longer tainted\n",
            taintedBranches.at(i));

            auto inst = std::move(taintedBranches.at(i));
            assert(inst);

            cpu->freeBranch(inst);
            taintedBranches.erase(taintedBranches.begin() + i);
            i--;
        }
    }
}


void
DelayUnit::insertDelayedMem(const DynInstPtr &inst)
{
    assert(inst->isLoad());
    ++stats.insertedDelayedMems;
    DPRINTF(DelayUnit, "Inserting delayed completion load [sn:%llu]"
    "into delay_unit\n", inst->seqNum);
    delayedMems.insert(delayedMems.begin() +
                           getPosition(delayedMems, inst->seqNum),
                       inst);
}

void
DelayUnit::freeDelayedMems()
{
    for (int i = 0; i < delayedMems.size(); i++) {
        if (cpu->scheme == CPU::Scheme::STT &&
            (!cpu->taintTracker.isTaintedInst(delayedMems.at(i)))) {
            ++stats.clearedDelayedMems;
            DPRINTF(DelayUnit, "Completing tainted load [sn:%llu] from "
            "delay_unit as it is no longer tainted post-prediction\n",
            delayedMems.at(i)->seqNum);

            cpu->freeLoad(delayedMems.at(i));
            delayedMems.erase(delayedMems.begin() + i);
            i--;
        } else if ((cpu->scheme == CPU::Scheme::Delay ||
                    cpu->scheme == CPU::Scheme::DoM) &&
                    !delayedMems.at(i)->isSpeculative()) {
            if (cpu->scheme == CPU::Scheme::Delay) {
                ++stats.clearedDelayedMems;
                DPRINTF(DelayUnit, "Released delayed load [sn:%llu] from "
                "delay_unit as it is no longer speculative\n",
                delayedMems.at(i)->seqNum);

                cpu->freeLoad(delayedMems.at(i));
                delayedMems.erase(delayedMems.begin() + i);
                i--;
            } else {
                //if (!delayedMems.at(i)->isSquashed() &&
                //    delayedMems.at(i)->predInst.shouldForward) {
                //    cpu->forwardLoad(delayedMems.at(i));
                //    delayedMems.erase(delayedMems.begin() + i);
                //    i--;
                //    continue;
                //}
                ++stats.reissuedDelayedMems;
                //TODO: This should have been cleared elsewhere
                if (!delayedMems.at(i)->isSquashed()) {
                    if (delayedMems.at(i)->savedRequest)
                    delayedMems.at(i)->savedRequest->deletePacket();
                    cpu->addReadyMemInst(delayedMems.at(i));
                }
                delayedMems.erase(delayedMems.begin() + i);
                i--;
            }
        }
    }
}

void
DelayUnit::updateStall()
{
    bool stall = true;

    if (!taintedLoads.empty())
        stall = stall && headLoad == taintedLoads.front()->seqNum;

    if (!taintedBranches.empty())
        stall = stall && headBranch == taintedBranches.front()->seqNum;

    if (!delayedMems.empty())
        stall = stall && headMem == delayedMems.front()->seqNum;

    if (taintedLoads.empty() && taintedBranches.empty() && delayedMems.empty())
        stall = false;

    if (stall) {
        stallCycles++;
    } else {
        stallCycles = 0;
    }
    assert(stallCycles < stallThreshold);

    DPRINTF(DelayDebug, "stalls: %d, LoadSeq: %d / %d, "
            "BranchSeq: %d / %d, MemSeq: %d / %d\n",
            stallCycles,
            headLoad,
            taintedLoads.empty() ? 0 : taintedLoads.front()->seqNum,
            headBranch,
            taintedBranches.empty() ? 0 : taintedBranches.front()->seqNum,
            headMem,
            delayedMems.empty() ? 0 : delayedMems.front()->seqNum);

    if (!taintedLoads.empty())
        headLoad = taintedLoads.front()->seqNum;
    if (!taintedBranches.empty())
        headBranch = taintedBranches.front()->seqNum;
    if (!delayedMems.empty())
        headMem = delayedMems.front()->seqNum;

}

void
DelayUnit::squashFromInst(InstSeqNum squash_num)
{
    int pos = getPosition(taintedLoads, squash_num);
    while (pos < taintedLoads.size()) {
        taintedLoads.pop_back();
    }
    pos = getPosition(taintedBranches, squash_num);
    while (pos < taintedBranches.size()) {
        taintedBranches.pop_back();
    }
    pos = getPosition(delayedMems, squash_num);
    while (pos < delayedMems.size()) {
        delayedMems.pop_back();
    }
}

uint
DelayUnit::cleanVector(std::vector<DynInstPtr> &vec)
{
    uint squashed = 0;
    for (int i = 0; i < vec.size(); i++) {
        if (vec.at(i)->isCommitted() || vec.at(i)->isSquashed()) {
            assert(!vec.at(i)->isCommitted());
            vec.erase(vec.begin() + i);
            i--;
            squashed++;
        }
    }
    return squashed;
}

void
DelayUnit::cleanAll()
{
    uint squashed = cleanVector(taintedLoads);
    stats.squashedTaintedLoads.operator+=(squashed);
    uint sq = cleanVector(taintedBranches);
    squashed += sq;
    stats.squashedTaintedBranches.operator+=(sq);
    sq = cleanVector(delayedMems);
    squashed += sq;
    stats.squashedDelayedMems.operator+=(sq);
    sq = cleanVector(freedTaintedLoads);
    squashed += sq;
    stats.squashedFreedTaintedLoads.operator+=(sq);
    DPRINTF(DelayDebug, "Squashed %d entries\n", squashed);
}

void
DelayUnit::sanityCheck()
{
    assert(taintedLoads.size() < 500);
    assert(freedTaintedLoads.size() < 500);
    assert(taintedBranches.size() < 500);
    assert(delayedMems.size() < 500);
    assert(freedDelayedMems.size() < 500);
}

void
DelayUnit::tick()
{
    freeTaintedLoads();
    freeTaintedBranches();
    freeDelayedMems();
    //cleanAll();
    if (cpu->stallDebug) updateStall();

    sanityCheck();
}

}
}
