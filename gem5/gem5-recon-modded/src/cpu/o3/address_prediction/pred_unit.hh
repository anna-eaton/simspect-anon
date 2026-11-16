#ifndef __CPU_O3_PRED_UNIT_HH__
#define __CPU_O3_PRED_UNIT_HH__

#include "cpu/o3/address_prediction/add_pred.hh"
#include "cpu/o3/comm.hh"
#include "cpu/o3/dyn_inst_ptr.hh"

namespace gem5
{

struct BaseO3CPUParams;

namespace o3
{

class CPU;

class PredictionUnit
{
    private:
        CPU* cpu;
        AddressPredictor addPred;

        std::vector<DynInstPtr> load_insts;

        std::vector<DynInstPtr> predicted_loads;

        std::vector<DynInstPtr> issued_preds;

        std::vector<DynInstPtr> ran_ahead_insts;

        std::map<Addr, int> runAhead;

        int stallCycles = 0;

        int predictionDelay = 0;

        bool pruneReadyInsts;

        bool pruneNonSpecInsts;

        InstSeqNum head_inst = 0;

        bool isPredictable(const DynInstPtr &load_inst);

        void cleanRunAhead();

        void cleanPredictions();

        void makePredictions();

        void increaseRunAhead(Addr pc);

        void decreaseRunAhead(Addr pc);

        void sanityCheck();


    public:

        PredictionUnit(CPU *_cpu, const BaseO3CPUParams &params);

        std::string name() const;

        int getPosition(std::vector<DynInstPtr> &vec, InstSeqNum seqNum);

        void insertLoad(const DynInstPtr &load_inst);

        bool hasLoads();

        bool hasPredictedLoads();

        DynInstPtr getPredictedLoad();

        void squashFromInst(InstSeqNum seqNum);

        void handleSquash(const DynInstPtr &inst);

        void insertIssuedLoad(const DynInstPtr &load_inst);

        void removeIssuedPrediction(const DynInstPtr &inst);

        void checkForStores(const DynInstPtr &store_inst,
                            const char* data);

        void completeLoad(const DynInstPtr &load_inst);

        bool onlyOneShadow();

        void checkStall();

        void tick();

    struct PredictionUnitStats : public statistics::Group
    {
        PredictionUnitStats(CPU *cpu);

        statistics::Scalar loadsInserted;
        statistics::Scalar completedLoads;
        statistics::Scalar loadsCleared;

        statistics::Scalar predictionsMade;
        statistics::Scalar predictionsIssued;
        statistics::Scalar predictionsCleared;

        statistics::Scalar issuedLoadsInserted;
        statistics::Scalar issuedLoadsCleared;

        statistics::Scalar storeForwards;
        statistics::Scalar partialStoreForwards;

        statistics::Scalar prunedReadyInsts;
        statistics::Scalar prunedNonSpecInsts;

    } stats;


};

}

}


#endif //_CPU_O3_PRED_UNIT_HH__
