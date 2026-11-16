/*
 * Copyright (c) 2004-2006 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "cpu/o3/store_set_annot.hh"

#include "base/logging.hh"
#include "base/trace.hh"
#include "debug/StoreSet.hh"

namespace gem5
{

namespace o3
{

AnnotatedStoreSet::AnnotatedStoreSet(
        uint64_t clear_period, int SSIT_size, int LFST_size,
        const std::vector<Addr> &annot_load_pcs,
        const std::vector<Addr> &annot_store_pcs)
    : StoreSet(clear_period, SSIT_size, LFST_size)
{
    if (annot_load_pcs.size() != annot_store_pcs.size()) {
        fatal("AnnotatedStoreSet: annotationLoadPCs and "
              "annotationForcedStorePCs must have the same length "
              "(got %u vs %u)",
              annot_load_pcs.size(), annot_store_pcs.size());
    }

    for (size_t i = 0; i < annot_load_pcs.size(); ++i) {
        Addr load_pc  = annot_load_pcs[i];
        Addr store_pc = annot_store_pcs[i];
        annotForcedStore[load_pc] = store_pc;
        DPRINTF(StoreSet,
                "AnnotatedStoreSet: forced dependency annotation: "
                "load %#x -> store %#x\n",
                load_pc, store_pc);
    }
}

InstSeqNum
AnnotatedStoreSet::checkInst(Addr PC)
{
    if (!annotForcedStore.empty()) {
        auto it = annotForcedStore.find(PC);
        if (it != annotForcedStore.end()) {
            Addr forced_store_pc = it->second;
            DPRINTF(StoreSet,
                    "AnnotatedStoreSet: annotation override for load %#x: "
                    "forcing into store set of store %#x\n",
                    PC, forced_store_pc);
            violation(forced_store_pc, PC);
        }
    }

    return StoreSet::checkInst(PC);
}

} // namespace o3
} // namespace gem5
