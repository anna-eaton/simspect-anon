#ifndef __CPU_O3_ADD_PRED_HH__
#define __CPU_O3_ADD_PRED_HH__

#include <vector>

#include "base/statistics.hh"

namespace gem5
{

struct BaseO3CPUParams;

namespace o3
{

class CPU;

class AddressPredictor
{


    private:
        CPU* cpu;

        bool unlimitedEntries = false;
        int numEntries;
        int associativity;
        int numSets;

        int inc;
        int dec;
        int sat;
        int thr;

        bool limitToPage;
        bool blockListMode = false;

    enum OperatingMode
    {
        Inactive,
        Simple,
        Complex,
        SimpleOp,
        ComplexOp,
        All
    } mode;

    struct EntryHistory
    {
        EntryHistory(){}

        std::vector<int> op1;
        std::vector<int> op2;

        std::vector<Addr> addresses;
    };

    struct Entry
    {
        Entry(Addr pc)
            : pc(pc)
        {
            history = std::make_unique<EntryHistory>();
        }

        Addr pc = 0;
        std::vector<Cycles> decodedCycles;
        int confidence = 0;
        uint32_t size = 0;
        std::unique_ptr<EntryHistory> history;
        Cycles lastUpdated = Cycles(0);

        bool isBlocked = false;
    };

    std::vector<std::vector<Entry *>> entries;



    private:
        Entry* getMatchingEntry(Addr pc);

        void insertNewEntry(Entry *entry);

        bool isSimpleStride(std::vector<Addr> addresses);

        Addr getStride(std::vector<Addr> addresses);


    public:

        AddressPredictor(CPU *_cpu, const BaseO3CPUParams &params);

        void updateConfidence(Addr pc, bool correct);

        void updatePredictor(Addr pc, Addr addr, Addr prediction,
                             uint32_t size, Cycles currCycle,
                             int op1 = 0, int op2 = 0);

        Addr getPrediction(Addr pc, int runAhead);

        int getSize(Addr pc);

    private:

    struct AddressPredictorStats : public statistics::Group
    {
        AddressPredictorStats(CPU *cpu);

        statistics::Scalar simpleStridesDetected;
        statistics::Scalar complexStridesDetected;
        statistics::Scalar operandSimpleStridesDetected;
        statistics::Scalar operandComplexStridesDetected;

        statistics::Scalar entriesInserted;
        statistics::Scalar entriesDeleted;

        statistics::Scalar failedPredictions;
        statistics::Scalar confidenceLimitedPredictions;
        statistics::Scalar pageLimitedPredictions;
        statistics::Scalar successfulPredictions;

        statistics::Scalar blockedEntries;
        statistics::Scalar blockedPredictions;

        statistics::Scalar staticLoadBypass;
    } stats;
};

}

}

#endif // __CPU_O3_ADD_PRED_HH__
