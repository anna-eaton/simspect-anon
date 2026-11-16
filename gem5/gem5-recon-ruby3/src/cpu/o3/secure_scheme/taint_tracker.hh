#ifndef __CPU_O3_TAINT_TRACKER_HH__
#define __CPU_O3_TAINT_TRACKER_HH__

#include <map>

#include "base/statistics.hh"
#include "cpu/o3/comm.hh"
#include "cpu/o3/dyn_inst_ptr.hh"
#include "cpu/reg_class.hh"

namespace gem5
{

struct BaseO3CPUParams;

namespace o3
{

class CPU;

class TaintTracker
{
    private:

        CPU *_cpu;

        std::map<PhysRegIdPtr, DynInstPtr> taints;

        void cleanTaints();

        void sanityCheck();

    public:
        TaintTracker(CPU *_cpu, const BaseO3CPUParams &params);

        void resetState();

        void insertTaintInst(const DynInstPtr &load_inst);

        void insertTaint(const PhysRegIdPtr &regId,
                         const DynInstPtr &load_inst);

        bool isTaintedInst(const DynInstPtr &load_inst);

        bool isTainted(const PhysRegIdPtr &regId);

        bool hasTaintedSrc(const DynInstPtr &inst);

        DynInstPtr getTaintSource(const PhysRegIdPtr &regId);

        void propagateTaints(const DynInstPtr &inst);

        DynInstPtr getOldestTaint(const DynInstPtr &inst);

        void freeTaints();

        void squashFromInst(InstSeqNum squash_num);

        void tick();

        void updateRevealedTaints(unsigned long int Addr);

    private:

        struct TaintTrackerStats : public Stats::Group
        {
            TaintTrackerStats(CPU *cpu);

            statistics::Scalar insertedTaintInsts;
            statistics::Scalar insertedTaints;
            statistics::Scalar freedTaints;
            statistics::Scalar allowlistedTaintsFromTT;
        } stats;

};

} // namespace o3
} // namespace gem5

#endif //_CPU_O3_TAINT_TRACKER_HH__
