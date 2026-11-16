#include "cpu/o3/address_prediction/add_pred.hh"

#include "cpu/o3/dyn_inst.hh"

namespace gem5
{

namespace o3
{

AddressPredictor::AddressPredictor(CPU *_cpu, const BaseO3CPUParams &params)
    : cpu(_cpu),
      numEntries(params.numPredictionEntries),
      associativity(params.predictionAssociativity),
      numSets(numEntries / associativity),
      inc(params.confidence_increment),
      dec(params.confidence_decrement),
      sat(params.confidence_saturation),
      thr(params.confidence_threshold),
      blockListMode(params.useBlockList),
      limitToPage(true),
      stats(cpu)
      {
        for (int i = 0; i < numSets; i++) {
            std::vector<Entry *> vec;
            entries.push_back(vec);
        }
      }

AddressPredictor::AddressPredictorStats::AddressPredictorStats(CPU *cpu)
    : statistics::Group(cpu, "address_predictor"),
        ADD_STAT(simpleStridesDetected, statistics::units::Count::get(),
                "Number of simple address strides detected"),
        ADD_STAT(complexStridesDetected, statistics::units::Count::get(),
                "Number of complex address strides detected"),
        ADD_STAT(operandSimpleStridesDetected, statistics::units::Count::get(),
                "Number of simple operand strides detected"),
        ADD_STAT(operandComplexStridesDetected,
                                            statistics::units::Count::get(),
                "Number of complex operand strides detected"),
        ADD_STAT(entriesInserted, statistics::units::Count::get(),
                "Number of prediction entries inserted"),
        ADD_STAT(entriesDeleted, statistics::units::Count::get(),
                "Number of prediction entries deleted"),
        ADD_STAT(failedPredictions, statistics::units::Count::get(),
                "Number of predictions returning 0"),
        ADD_STAT(confidenceLimitedPredictions, statistics::units::Count::get(),
                "Number of predictions blocked due to low confidence"),
        ADD_STAT(pageLimitedPredictions, statistics::units::Count::get(),
                "Number of predictions blocked due to page limits"),
        ADD_STAT(successfulPredictions, statistics::units::Count::get(),
                "Number of successful predictions"),
        ADD_STAT(blockedEntries, statistics::units::Count::get(),
                "Number of entries that are blocklisted"),
        ADD_STAT(blockedPredictions, statistics::units::Count::get(),
                "Number of predictions blocked due to blocklist"),
        ADD_STAT(staticLoadBypass, statistics::units::Count::get(),
                "Number of predictions allowed due to static address")
{

}

AddressPredictor::Entry*
AddressPredictor::getMatchingEntry(Addr pc)
{
    auto set = &entries.at(pc % numSets);
    if (set->size() == 0) return nullptr;
    for (int i = 0; i < set->size(); i++) {
        if (set->at(i)->pc == pc) {
            return set->at(i);
        }
    }
    return nullptr;
}

void
AddressPredictor::insertNewEntry(Entry *entry)
{
    ++stats.entriesInserted;

    auto set = &(entries.at(entry->pc % numSets));
    if (set->size() < associativity ||
        unlimitedEntries) {
        set->push_back(entry);
        return;
    }
    int oldest = 0;
    for (int i = 1; i < associativity; i++) {
        if (set->at(i)->lastUpdated <
            set->at(oldest)->lastUpdated) {
            oldest = i;
        }
    }
    delete set->at(oldest);
    set->at(oldest) = entry;
    ++stats.entriesDeleted;
}

bool
AddressPredictor::isSimpleStride(std::vector<Addr> addresses)
{
    if (addresses.size() < 3) return false;
    for (int i = 0; i < addresses.size(); i++) {
        Addr first = addresses.at(addresses.size() - (i + 3));
        Addr second = addresses.at(addresses.size() - (i + 2));
        Addr third = addresses.at(addresses.size() - (i + 1));
        return (third - second) == (second - first);
    }
    return false;
}

Addr
AddressPredictor::getStride(std::vector<Addr> addresses)
{
    if (isSimpleStride(addresses)) {
        return addresses.back() - (addresses.at(addresses.size() - 2));
    }
    return 0;
}

void
AddressPredictor::updateConfidence(Addr pc, bool correct)
{
    Entry* entry = getMatchingEntry(pc);

    if (!entry) return;

    if (blockListMode && !correct) {
        entry->isBlocked = true;
        ++stats.blockedEntries;
    }

    if (correct) {
        entry->confidence += inc;
    } else {
        entry->confidence -= dec;
    }
    if (entry->confidence < 0) {
        entry->confidence = 0;
    } else if (entry->confidence > sat) {
        entry->confidence = sat;
    }
}

void
AddressPredictor::updatePredictor(Addr pc, Addr addr,
                                  Addr prediction, uint32_t size,
                                  Cycles currCycle,
                                  int op1, int op2)
{
    Entry* entry = getMatchingEntry(pc);

    if (!entry) {
        entry = new Entry(pc);
        entry->size = size;
        insertNewEntry(entry);
    }
    assert(entry);
    entry->lastUpdated = currCycle;

    if (!isSimpleStride(entry->history->addresses)) {
        updateConfidence(pc, false);
    } else {
        Addr stride = getStride(entry->history->addresses);
        Addr base = entry->history->addresses.back();
        Addr prediction = base + stride;
        updateConfidence(pc, addr == prediction);
    }

    entry->history->addresses.push_back(addr);

    if (entry->history->addresses.size() > 8) {
        entry->history->addresses.erase(entry->history->addresses.begin());
    }
}

Addr
AddressPredictor::getPrediction(Addr pc, int runAhead)
{
    Entry* entry = getMatchingEntry(pc);
    ++stats.failedPredictions;

    if (!entry) return 0;
    if (!isSimpleStride(entry->history->addresses)) return 0;

    if (getStride(entry->history->addresses) > 128) return 0;

    if (entry->confidence < thr) {
        if (getStride(entry->history->addresses) == 0 &&
            entry->confidence > 0) {
            ++stats.staticLoadBypass;
        } else {
            ++stats.confidenceLimitedPredictions;
            return 0;
        }
    }

    if (entry->isBlocked) {
        ++stats.blockedPredictions;
        return 0;
    }

    Addr target = entry->history->addresses.back() +
          (runAhead * getStride(entry->history->addresses));

    --stats.failedPredictions;

    if (limitToPage &&
        ((target >> 12) !=
         (entry->history->addresses.back() >> 12))) {
        ++stats.pageLimitedPredictions;
        return 0;
    }

    ++stats.successfulPredictions;
    return target;
}

int
AddressPredictor::getSize(Addr pc)
{
    Entry* entry = getMatchingEntry(pc);
    if (!entry) return 0;
    return entry->size;
}

}
}
