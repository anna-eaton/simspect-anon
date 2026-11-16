#ifndef __CPU_O3_SHADOW_TRACKER_HH__
#define __CPU_O3_SHADOW_TRACKER_HH__

#include "base/statistics.hh"
#include "cpu/o3/comm.hh"
#include "cpu/o3/dyn_inst_ptr.hh"
#include "cpu/o3/limits.hh"
#include "cpu/timebuf.hh"

namespace gem5
{

struct BaseO3CPUParams;

namespace o3
{

class CPU;

class ShadowTracker
{
    public:

        ShadowTracker(CPU *_cpu, const BaseO3CPUParams &params);

        std::string name() const;

        void insertException(DynInstPtr inst);

        void insertBranch(DynInstPtr inst);

        void insertStore(DynInstPtr inst);

        void insertSpecInst(DynInstPtr inst);

        bool hasShadow();

        InstSeqNum getOldestShadow();

        InstSeqNum getOldestBranchShadow();

        bool hasSpecInst();

        InstSeqNum getOldestSpecInst();

        void squashFromInst(InstSeqNum squash_num);

        void tick();

        bool onlyOneShadow(DynInstPtr inst);

    private:

        CPU *cpu;

        void startupStage();

        void freeExceptions();

        void freeBranches();

        void freeStores();

        void freeSpecInsts();

        uint cleanVector(std::vector<DynInstPtr> &vec);

        void clearDeadEntries();

        void sanityCheck();

        std::vector<DynInstPtr> exceptions;
        std::vector<DynInstPtr> branches;
        std::vector<DynInstPtr> stores;

        std::vector<DynInstPtr> spec_insts;

        struct ShadowTrackerStats : public statistics::Group
        {
            ShadowTrackerStats(CPU *cpu);

            statistics::Scalar insertedBranches;
            statistics::Scalar freedBranches;
            statistics::Scalar squashedBranches;

            statistics::Scalar insertedStores;
            statistics::Scalar freedStores;
            statistics::Scalar squashedStores;

            statistics::Scalar insertedSpecInsts;
            statistics::Scalar freedSpecInsts;
            statistics::Scalar squashedSpecInsts;

            statistics::Scalar shadowLimitedPredictions;

        } stats;
};


} // namespace o3
} // namespace gem5

#endif //__CPU_O3_SHADOW_TRACKER_HH__
