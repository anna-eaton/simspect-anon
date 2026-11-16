#include "cpu/o3/address_prediction/pred_unit.hh"

#include "cpu/o3/dyn_inst.hh"
#include "debug/PredictionUnit.hh"
#include "params/BaseO3CPU.hh"

namespace gem5
{

namespace o3
{

PredictionUnit::PredictionUnit(CPU *_cpu, const BaseO3CPUParams &params)
    : cpu(_cpu),
      addPred(cpu, params),
      predictionDelay(params.predictionDelay),
      pruneReadyInsts(params.pruneReadyInsts),
      pruneNonSpecInsts(params.pruneNonSpecInsts),
      stats(_cpu)
{
}

std::string
PredictionUnit::name() const
{
    return cpu->name() + ".prediction_unit";
}

PredictionUnit::PredictionUnitStats::PredictionUnitStats(CPU *cpu)
    : statistics::Group(cpu, "prediction_unit"),
        ADD_STAT(loadsInserted, statistics::units::Count::get(),
                "Number of loads inserted for prediction"),
        ADD_STAT(completedLoads, statistics::units::Count::get(),
                "Number of committed loads received"),
        ADD_STAT(loadsCleared, statistics::units::Count::get(),
                "Number of loads squashed or cleared"),
        ADD_STAT(predictionsMade, statistics::units::Count::get(),
                "Number of predictions made from loads"),
        ADD_STAT(predictionsIssued, statistics::units::Count::get(),
                "Number of predictions issued to translation"),
        ADD_STAT(predictionsCleared, statistics::units::Count::get(),
                "Number of predictions squashed or cleared"),
        ADD_STAT(issuedLoadsInserted, statistics::units::Count::get(),
                "Number of issued predictions tracked"),
        ADD_STAT(issuedLoadsCleared, statistics::units::Count::get(),
                "Number of issued predictions squashed"),
        ADD_STAT(storeForwards, statistics::units::Count::get(),
                "Number of times stores forwarded to a predictions"),
        ADD_STAT(partialStoreForwards, statistics::units::Count::get(),
                "Number of times a partial store forwarding happened"),
      ADD_STAT(prunedReadyInsts, statistics::units::Count::get(),
               "Number of loads pruned due to being ready to issue"),
      ADD_STAT(prunedNonSpecInsts, statistics::units::Count::get(),
               "Number of loads pruned due to being non-speculative")
    {

    }

bool
PredictionUnit::isPredictable(const DynInstPtr &load_inst)
{
return !(load_inst->isReadBarrier() ||
         load_inst->isSyscall() ||
         load_inst->isHtmCmd()  ||
         load_inst->isControl() ||
         load_inst->isNonSpeculative() ||
         load_inst->isAtomic() ||
         load_inst->isDataPrefetch() ||
         load_inst->isCall() ||
         load_inst->isFullMemBarrier());
}

int
PredictionUnit::getPosition(std::vector<DynInstPtr> &vec, InstSeqNum seqNum)
{
    int i = 0;
    for (; i < vec.size(); i++) {
        if (vec.at(i)->seqNum > seqNum)
            return i;
    }
    return i;
}


void
PredictionUnit::cleanRunAhead()
{
    while (!ran_ahead_insts.empty() &&
           ran_ahead_insts.front()->isSquashed()) {
        if (ran_ahead_insts.front()->predInst.hasRunAhead) {
            decreaseRunAhead(ran_ahead_insts.front()->pcState().instAddr());
            ran_ahead_insts.front()->predInst.hasRunAhead = false;
        }
        ran_ahead_insts.erase(ran_ahead_insts.begin());
    }
}

void
PredictionUnit::cleanPredictions()
{
    for (int i = 0; i < predicted_loads.size(); i++) {
        DynInstPtr inst = predicted_loads.at(i);
        if (inst->isSquashed() || inst->isIssued()) {
            predicted_loads.erase(predicted_loads.begin() + i);
            i--;
        }
    }
}

void
PredictionUnit::makePredictions()
{

    while (!load_insts.empty() &&
            (cpu->curCycle() -
            load_insts.front()->predInst.decodedCycle
            >= Cycles(predictionDelay))) {

        DynInstPtr inst = std::move(load_insts.front());
        load_insts.erase(load_insts.begin());

        if (inst->isSquashed()) continue;

        if (inst->isIssued()) {
            continue;
        }

        if (pruneReadyInsts &&
            inst->readyToIssue()) {
            ++stats.prunedReadyInsts;
            continue;
        }

        if (pruneNonSpecInsts &&
            (!inst->isSpeculative())) {
            ++stats.prunedNonSpecInsts;
            continue;
        }

        increaseRunAhead(inst->pcState().instAddr());
        inst->predInst.hasRunAhead = true;

        ran_ahead_insts.push_back(inst);

        Addr pred = addPred.getPrediction(inst->pcState().instAddr(),
                              runAhead.at(inst->pcState().instAddr()));
        if (pred == 0) continue;

        DPRINTF(PredictionUnit, "Made prediction on load [sn:%llu] "
                "with pc %llx and pred addr %#x\n",
                inst->seqNum,
                inst->pcState().instAddr(),
                pred);
        ++stats.predictionsMade;

        inst->predInst.hasPred = true;
        inst->predInst.predictedAddress = pred;
        inst->predInst.predictedSize =
                          addPred.getSize(inst->pc->instAddr());
        predicted_loads.push_back(inst);
    }
}

void
PredictionUnit::increaseRunAhead(Addr pc)
{
    if (runAhead.count(pc) == 0) {
        runAhead.insert(std::pair<Addr, int>(pc, 0));
    }
    runAhead.at(pc)++;
    assert(runAhead.at(pc) > 0);
}

void
PredictionUnit::decreaseRunAhead(Addr pc)
{
    assert(runAhead.count(pc) != 0);
    runAhead.at(pc)--;
    assert(runAhead.at(pc) >= 0);
}

void
PredictionUnit::sanityCheck()
{
    assert(ran_ahead_insts.size() < 500);
    assert(load_insts.size() < 500);
    assert(issued_preds.size() < 500);
    assert(predicted_loads.size() < 500);
}

void
PredictionUnit::insertLoad(const DynInstPtr &load_inst)
{
    if (!isPredictable(load_inst)) return;
    ++stats.loadsInserted;

    load_insts.push_back(load_inst);
}

bool
PredictionUnit::hasLoads()
{
    return !load_insts.empty();
}

bool
PredictionUnit::hasPredictedLoads()
{
    return !predicted_loads.empty();
}

DynInstPtr
PredictionUnit::getPredictedLoad()
{
    ++stats.predictionsIssued;

    DynInstPtr inst = std::move(predicted_loads.front());
    predicted_loads.erase(predicted_loads.begin());
    return inst;
}

void
PredictionUnit::squashFromInst(InstSeqNum seqNum) {
    while (!ran_ahead_insts.empty() &&
            ran_ahead_insts.back()->seqNum > seqNum) {
        handleSquash(ran_ahead_insts.back());
        ran_ahead_insts.erase(ran_ahead_insts.end() - 1);
    }

    int pos = getPosition(issued_preds, seqNum);
    assert(pos == issued_preds.size());
}

void
PredictionUnit::handleSquash(const DynInstPtr &inst)
{
    if (inst->isLoad())
        DPRINTF(PredictionUnit, "Handling squash for load [sn:%llu]\n",
                inst->seqNum);

    if (inst->predInst.hasRunAhead) {
        decreaseRunAhead(inst->pcState().instAddr());
        inst->predInst.hasRunAhead = false;
    }

    removeIssuedPrediction(inst);
}

void
PredictionUnit::insertIssuedLoad(const DynInstPtr &load_inst)
{
    ++stats.issuedLoadsInserted;
    issued_preds.insert(issued_preds.begin() +
                            getPosition(issued_preds, load_inst->seqNum),
                        load_inst);}

void
PredictionUnit::removeIssuedPrediction(const DynInstPtr &inst)
{
    auto it = std::find(issued_preds.begin(),
                issued_preds.end(), inst);

    if (it != issued_preds.end()) {
        issued_preds.erase(it);
    }

    if (inst->predInst.predRequest &&
       (!inst->predInst.predRequest->isReleased())) {
        inst->predInst.predRequest->discard();
    }
}


void
PredictionUnit::checkForStores(const DynInstPtr &store_inst,
                               const char* data)
{
    DPRINTF(PredictionUnit, "Checking committed store [sn:%llu] for "
            "potential issued prediction forwarding\n",
            store_inst->seqNum);
    if (store_inst->effSize == 0) return;

    assert(!store_inst->isAtomic());

    for (int i = 0; i < issued_preds.size(); i++) {
        DynInstPtr &ld = issued_preds.at(i);

        assert(ld->predInst.predRequest);

        if (ld->seqNum < store_inst->seqNum ||
           (ld->predInst.storeSeqNum > store_inst->seqNum))
            continue;

        auto ld_s = ld->predInst.predictedAddress;
        auto ld_e = ld_s + ld->predInst.predictedSize;

        auto st_s = store_inst->effAddr;
        auto st_e = st_s + store_inst->effSize;

        bool st_ll = ld_s >= st_s;
        bool st_ul = ld_e <= st_e;

        bool ll_sp = ld_s < st_e;
        bool ul_sp = ld_e > st_s;

        if (st_ll && st_ul) {
            DPRINTF(PredictionUnit, "Found full forwarding between "
                "store [sn:%llu] and load [sn:%llu]\n",
                store_inst->seqNum,
                ld->seqNum);
            ++stats.storeForwards;

            ld->predInst.validStoreData = true;
            ld->predInst.storeSeqNum = store_inst->seqNum;
            ld->predInst.partial = false;
            ld->predInst.storeWriteCycle = cpu->curCycle();

            if (!ld->predInst.storeData) {
                ld->predInst.storeData =
                    new uint8_t[ld->predInst.predictedSize];
            }

            int shift_amt = ld->predInst.predictedAddress -
                store_inst->effAddr;

            assert(data);

            memcpy(ld->predInst.storeData,
                   data + shift_amt,
                   ld->predInst.predictedSize);

        } else if ((st_ll && ll_sp) ||
            (st_ul && ul_sp) ||
            (ll_sp && ul_sp)) {

            DPRINTF(PredictionUnit, "Found partial forwarding between "
                "store [sn:%llu] and load [sn:%llu]\n",
                store_inst->seqNum,
                ld->seqNum);
            ++stats.partialStoreForwards;

            ld->predInst.partial = true;
            ld->predInst.storeSeqNum = store_inst->seqNum;
            ld->predInst.storeWriteCycle = cpu->curCycle();
        }
    }
}

void
PredictionUnit::completeLoad(const DynInstPtr &load_inst)
{
    if (!isPredictable(load_inst)) return;

    DPRINTF(PredictionUnit, "Updating prediction unit with "
            "load [sn:%llu]\n", load_inst->seqNum);
    ++stats.completedLoads;

    if (load_inst->predInst.hasRunAhead) {
        auto pos = std::find(ran_ahead_insts.begin(),
                            ran_ahead_insts.end(),
                            load_inst);

        assert(pos != ran_ahead_insts.end());
        ran_ahead_insts.erase(pos);

        decreaseRunAhead(load_inst->pcState().instAddr());
        load_inst->predInst.hasRunAhead = false;
    }

    if (load_inst->predInst.successfulPred) {
        assert(issued_preds.front() == load_inst);
        issued_preds.erase(issued_preds.begin());
    }

    if (load_inst->predInst.predRequest &&
        !load_inst->predInst.predRequest->isReleased())
        load_inst->predInst.predRequest->discard();

    addPred.updatePredictor(load_inst->pcState().instAddr(),
                            load_inst->effAddr,
                            load_inst->predInst.predictedAddress,
                            load_inst->effSize,
                            cpu->curCycle());
}

bool
PredictionUnit::onlyOneShadow()
{
    return cpu->shadowTracker.onlyOneShadow(predicted_loads.front());
}

void
PredictionUnit::checkStall()
{
    if (issued_preds.empty()) {
        stallCycles = 0;
        head_inst = 0;
        return;
    }

    if (head_inst == 0) {
        stallCycles = 0;
        head_inst = issued_preds.front()->seqNum;
        return;
    }

    if (head_inst == issued_preds.front()->seqNum) {
        stallCycles++;
    } else {
        stallCycles = 0;
        head_inst = issued_preds.front()->seqNum;
    }

    assert(stallCycles < 10000);
}

void
PredictionUnit::tick()
{
    //Never clears anything
    //cleanLoads();
    //Never clears anything
    //cleanPredictions();
    //cleanIssued();
    cleanRunAhead();
    cleanPredictions();
    makePredictions();
    if (cpu->stallDebug) checkStall();

    sanityCheck();
}

}

}
