#ifndef __CPU_O3_PRED_INST_HH__
#define __CPU_O3_PRED_INST_HH__

#include "base/types.hh"
#include "cpu/inst_seq.hh"
#include "cpu/o3/dyn_inst_ptr.hh"
#include "cpu/o3/lsq.hh"

namespace gem5
{

namespace o3
{
class PredictionInstruction
{
    public:
        PredictionInstruction() {};

        ~PredictionInstruction() {
            if (predData) {
                delete [] predData;
                predData = nullptr;
            }
            if (storeData) {
                delete [] storeData;
                predData = nullptr;
            }
            if (verifyData) {
                delete [] verifyData;
                predData = nullptr;
            }
            assert(!predRequest);
        }

        Addr predictedAddress = 0;

        Addr physPredAddr = 0;

        uint8_t *predData = nullptr;

        uint8_t *storeData = nullptr;

        uint8_t *verifyData = nullptr;

        bool validPredData = false;

        bool validStoreData = false;

        bool hasPred = false;

        bool successfulPred = false;

        bool shouldForward = false;

        bool partial = false;

        bool hasRunAhead = false;

        bool wrotePredictedData = false;

        Cycles decodedCycle = Cycles(0);

        Cycles predIssuedCycle = Cycles(0);

        Cycles predCompleteCycle = Cycles(0);

        Cycles addressCalculatedCycle = Cycles(0);

        Cycles loadCompleteCycle = Cycles(0);

        Cycles storeWriteCycle = Cycles(0);

        InstSeqNum storeSeqNum = 0;

        uint32_t predictedSize = 0;

        LSQ::LSQRequest* predRequest = nullptr;

        Request::Flags flags = 0x0000;

        int cacheLevels = 0;
};

}

}


#endif //_CPU_O3_PRED_INST_HH__
