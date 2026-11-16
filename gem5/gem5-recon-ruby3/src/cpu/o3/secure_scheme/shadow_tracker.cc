#include "cpu/o3/secure_scheme/shadow_tracker.hh"

#include "config/the_isa.hh"
#include "cpu/inst_seq.hh"
#include "cpu/o3/dyn_inst.hh"
#include "cpu/o3/limits.hh"
#include "debug/ShadowDebug.hh"
#include "params/BaseO3CPU.hh"

namespace gem5
{

namespace o3
{

ShadowTracker::ShadowTracker(CPU *_cpu, const BaseO3CPUParams &params)
    : cpu(_cpu),
      stats(cpu)
{

}

std::string
ShadowTracker::name() const
{
    return cpu->name() + ".shadow_tracker";
}

ShadowTracker::ShadowTrackerStats::ShadowTrackerStats(CPU *cpu)
    : statistics::Group(cpu, "shadow_tracker"),
        ADD_STAT(insertedBranches, statistics::units::Count::get(),
                "Number of branches inserted into shadow tracker"),
        ADD_STAT(freedBranches, statistics::units::Count::get(),
                "Number of branches freed from shadow tracker"),
        ADD_STAT(squashedBranches, statistics::units::Count::get(),
                "Number of branches squashed in shadow tracker"),
        ADD_STAT(insertedStores, statistics::units::Count::get(),
                "Number of stores inserted into shadow tracker"),
        ADD_STAT(freedStores, statistics::units::Count::get(),
                "Number of stores freed from shadow tracker"),
        ADD_STAT(squashedStores, statistics::units::Count::get(),
                "Number of stores squashed in shadow tracker"),
        ADD_STAT(insertedSpecInsts, statistics::units::Count::get(),
                "Number of spec insts inserted into shadow tracker"),
        ADD_STAT(freedSpecInsts, statistics::units::Count::get(),
                "Number of spec insts freed from shadow tracker"),
        ADD_STAT(squashedSpecInsts, statistics::units::Count::get(),
                "Number of spec insts squashed in shadow tracker"),
        ADD_STAT(shadowLimitedPredictions, statistics::units::Count::get(),
                "Number of predictions blocked due to too many shadows")



    {
    }

//Currently unusued, no easy way to check for possible exceptions
void
ShadowTracker::insertException(DynInstPtr inst)
{
    exceptions.push_back(inst);
}

void
ShadowTracker::insertBranch(DynInstPtr inst)
{
    ++stats.insertedBranches;
    branches.push_back(inst);
}

void
ShadowTracker::insertStore(DynInstPtr inst)
{
    ++stats.insertedStores;
    stores.push_back(inst);
}

void
ShadowTracker::insertSpecInst(DynInstPtr inst)
{
    assert(hasShadow());
    ++stats.insertedSpecInsts;
    inst->setSpeculative(true);
    spec_insts.push_back(inst);
}

bool
ShadowTracker::hasShadow()
{
    return !(exceptions.empty() &&
             branches.empty()   &&
             stores.empty());
}

InstSeqNum
ShadowTracker::getOldestShadow()
{
    assert(hasShadow());
    DynInstPtr ex, br, st;
    if (!exceptions.empty())
        ex = exceptions.front();
    if (!branches.empty())
        br = branches.front();
    if (!stores.empty())
        st = stores.front();
    InstSeqNum min;
    if (ex)
        min = ex->seqNum;
    else if (br)
        min = br->seqNum;
    else
        min = st->seqNum;

    if (br && br->seqNum < min) min = br->seqNum;
    if (st && st->seqNum < min) min = st->seqNum;
    return min;
}

InstSeqNum
ShadowTracker::getOldestBranchShadow()
{
    if (branches.empty()) {
        return 0;
    }
    return branches.front()->seqNum;
}


bool
ShadowTracker::hasSpecInst()
{
    return !spec_insts.empty();
}

InstSeqNum
ShadowTracker::getOldestSpecInst()
{
    assert(hasSpecInst());
    return spec_insts.front()->seqNum;
}

void
ShadowTracker::squashFromInst(InstSeqNum squash_num)
{
    while (exceptions.size() > 0 &&
           exceptions.back()->seqNum > squash_num)
        exceptions.pop_back();
    while (branches.size() > 0 &&
           branches.back()->seqNum > squash_num)
        branches.pop_back();
    while (stores.size() > 0 &&
           stores.back()->seqNum > squash_num)
        stores.pop_back();
    while (spec_insts.size() > 0 &&
           spec_insts.back()->seqNum > squash_num) {
        spec_insts.back()->setSpeculative(false);
        spec_insts.pop_back();
    }
}

void
ShadowTracker::tick()
{
    freeExceptions();
    freeBranches();
    freeStores();

    //clearDeadEntries();

    freeSpecInsts();

    sanityCheck();
}

bool
ShadowTracker::onlyOneShadow(DynInstPtr inst)
{
    int store_shadows = 0;
    int branch_shadows = 0;

    auto it = branches.begin();
    while (it != branches.end() &&
        (*it)->seqNum < inst->seqNum) {
        branch_shadows++;
        it++;
    }

    it = stores.begin();
    while (it != stores.end() &&
        (*it)->seqNum < inst->seqNum) {
        store_shadows++;
        it++;
    }

    if ((store_shadows + branch_shadows) > 1)
        ++stats.shadowLimitedPredictions;
    return (store_shadows + branch_shadows) <= 1;
}

void
ShadowTracker::startupStage()
{

}

void
ShadowTracker::freeExceptions()
{
    for (int i = 0; i < exceptions.size(); i++) {
        if (exceptions.at(i)->readyToCommit()) {
            exceptions.erase(exceptions.begin() + i);
            i--;
        }
    }
}

void
ShadowTracker::freeBranches()
{
    while (branches.size() > 0 &&
           branches.front()->branchResolved()) {
//           branches.front()->nowVisible) {
        ++stats.freedBranches;
        branches.erase(branches.begin());
    }
}

void
ShadowTracker::freeStores()
{
    while (stores.size() > 0 &&
           stores.front()->effAddrValid()) {
        ++stats.freedStores;
        stores.erase(stores.begin());
    }
}

uint
ShadowTracker::cleanVector(std::vector<DynInstPtr> &vec)
{
    uint squashed = 0;
    for (int i = 0; i < vec.size(); i++) {
        if (vec.at(i)->isCommitted() ||
            vec.at(i)->isSquashed()) {
            vec.erase(vec.begin() + i);
            i--;
            squashed++;
        }
    }
    return squashed;
}

void
ShadowTracker::clearDeadEntries()
{
    uint squashed = cleanVector(exceptions);
    uint sq = cleanVector(branches);
    stats.squashedBranches.operator+=(sq);
    squashed += sq;
    sq = cleanVector(stores);
    stats.squashedStores.operator+=(sq);
    squashed += sq;
    sq = cleanVector(spec_insts);
    stats.squashedSpecInsts.operator+=(sq);
    squashed += sq;
    DPRINTF(ShadowDebug, "Squashed %d entries\n", squashed);
}

void
ShadowTracker::sanityCheck()
{
    assert(exceptions.size() < 500);
    assert(branches.size() < 500);
    assert(stores.size() < 500);
    assert(spec_insts.size() < 500);
}

void
ShadowTracker::freeSpecInsts()
{
    if (!hasShadow()) {
        while (spec_insts.size() > 0) {
            ++stats.freedSpecInsts;
            spec_insts.back()->setSpeculative(false);
            spec_insts.pop_back();
        }
    }
    while (spec_insts.size() > 0 &&
           spec_insts.front()->seqNum <= getOldestShadow()) {
        ++stats.freedSpecInsts;
        spec_insts.front()->setSpeculative(false);
        spec_insts.erase(spec_insts.begin());
    }
}

} // namespace o3
} // namespace gem5
