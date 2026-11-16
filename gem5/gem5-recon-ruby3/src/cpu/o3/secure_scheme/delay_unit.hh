#ifndef __CPU_O3_DELAY_UNIT_HH__
#define __CPU_O3_DELAY_UNIT_HH__

#include "base/statistics.hh"
#include "cpu/o3/comm.hh"
#include "cpu/o3/dyn_inst_ptr.hh"

namespace gem5
{

struct BaseO3CPUParams;

namespace o3
{

class CPU;

class DelayUnit
{

    public:
        DelayUnit(CPU *_cpu, const BaseO3CPUParams &params);

        std::string name() const;

    private:
        int getPosition(std::vector<DynInstPtr> &vec, InstSeqNum seqNum);

        uint cleanVector(std::vector<DynInstPtr> &vec);

        void cleanAll();

        void sanityCheck();

    public:
        void insertTaintedLoad(const DynInstPtr &inst);

        void freeTaintedLoads();

        bool hasFreedTaintedLoads();

        DynInstPtr getFreedTaintedLoad();

        bool hasTaintedBranch(const DynInstPtr &inst);

        void insertTaintedBranch(const DynInstPtr &inst);

        void freeTaintedBranches();

        void insertDelayedMem(const DynInstPtr &inst);

        void freeDelayedMems();

        void updateStall();

        void squashFromInst(InstSeqNum squash_num);

        void tick();

    private:
        CPU *cpu;

        uint stallCycles = 0;
        uint stallThreshold = 10000;
        InstSeqNum headLoad = 0;
        InstSeqNum headBranch = 0;
        InstSeqNum headMem = 0;


        std::vector<DynInstPtr> taintedLoads;
        std::vector<DynInstPtr> freedTaintedLoads;
        std::vector<DynInstPtr> taintedBranches;
        std::vector<DynInstPtr> delayedMems;
        std::vector<DynInstPtr> freedDelayedMems;

        struct DelayUnitStats : public statistics::Group
        {
            DelayUnitStats(CPU *cpu);

            statistics::Scalar insertedTaintedLoads;
            statistics::Scalar clearedTaintedLoads;
            statistics::Scalar squashedTaintedLoads;

            statistics::Scalar insertedTaintedBranches;
            statistics::Scalar clearedTaintedBranches;
            statistics::Scalar squashedTaintedBranches;

            statistics::Scalar insertedDelayedMems;
            statistics::Scalar clearedDelayedMems;
            statistics::Scalar squashedDelayedMems;

            statistics::Scalar reissuedDelayedMems;

            statistics::Scalar squashedFreedTaintedLoads;
            statistics::Scalar allowlistedLoadsFromDU;
        } stats;
};

} //namespace o3
} //namespace gem5

#endif //__CPU_O3_DELAY_UNIT_HH
