
#include "mem/ruby/slicc_interface/SimSpectRubyHooks.hh"

#include <map>
#include <set>
#include <tuple>
#include <vector>

#include "mem/packet.hh"
#include "mem/protocol/RubyRequestType.hh"
#include "mem/request.hh"
#include "mem/ruby/slicc_interface/RubyRequest.hh"
#include "mem/ruby/structures/CacheMemory.hh"

namespace SimSpect {

MsgCtx g_msg;

namespace {

struct TransCtx
{
    std::string machine;
    int version;
    std::string event;
    std::string state;
    std::string statePerm;
    Addr addr;
    bool allocated;
    bool deallocated;
    bool tbeAlloc;
    uint64_t hmId;
    std::vector<std::string> pending;
};

std::vector<TransCtx> g_trans;
std::map<const CacheMemory *, std::string> g_structName;
typedef std::tuple<std::string, int, Addr> LineKey;
std::map<LineKey, std::string> g_resident;
std::map<LineKey, std::pair<std::string, bool> > g_lastStable;
std::map<Addr, std::string> g_lineReq;
std::map<LineKey, std::tuple<uint64_t, Addr, uint64_t> > g_rollback;
std::set<std::pair<const void *, Addr> > g_waitSeen;

bool
isPresentPerm(const std::string &p)
{
    return p == "Read_Only" || p == "Read_Write" || p == "Maybe_Stale";
}

bool
contains(const std::string &s, const char *sub)
{
    return s.find(sub) != std::string::npos;
}

bool
startsWith(const std::string &s, const char *p)
{
    return s.compare(0, std::string(p).size(), p) == 0;
}

const std::string &
structOf(const CacheMemory *cm)
{
    auto it = g_structName.find(cm);
    if (it != g_structName.end())
        return it->second;
    std::string n = cm->name();
    std::string s;
    if (contains(n, "L1Dcache"))
        s = "L1D";
    else if (contains(n, "L1Icache"))
        s = "L1I";
    else if (contains(n, "L2cache"))
        s = "L2";
    else {
        size_t dot = n.rfind('.');
        s = (dot == std::string::npos) ? n : n.substr(dot + 1);
    }
    return g_structName[cm] = s;
}

std::string
lineReq(Addr line)
{
    auto it = g_lineReq.find(lineOf(line));
    return it == g_lineReq.end() ? std::string("coh") : it->second;
}

void
attr(uint64_t &seq, Addr &pc, std::string &req)
{
    seq = NONE;
    pc = NONE;
    req = "-";
    if (!g_msg.valid)
        return;
    if (g_msg.isCpu) {
        seq = g_msg.seq;
        pc = g_msg.pc;
        req = g_msg.req;
    } else {
        getLineAttr(g_msg.line, seq, pc);
        req = lineReq(g_msg.line);
    }
}

TransCtx *
cur()
{
    return g_trans.empty() ? nullptr : &g_trans.back();
}

LineKey
keyFor(const TransCtx *t, Addr a)
{
    return LineKey(t ? t->machine : std::string("?"), t ? t->version : -1,
                   lineOf(a));
}

std::string
machineStruct(const TransCtx *t)
{
    if (t->machine == "L1Cache") {
        auto it = g_resident.find(keyFor(t, t->addr));
        if (it != g_resident.end())
            return it->second;
        return g_msg.valid && g_msg.isIfetch ? "L1I" : "L1D";
    }
    if (t->machine == "L2Cache")
        return "L2";
    if (t->machine == "Directory")
        return "DIR";
    return t->machine;
}

Kv
ctxKv(const std::string &req)
{
    Kv kv;
    kv.str("req", req);
    if (g_msg.valid) {
        kv.str("msg", g_msg.msg);
        if (g_msg.isCpu) {
            kv.hex("addr", g_msg.addr);
            kv.dec("size", g_msg.size);
        }
    }
    return kv;
}

uint64_t
rEmit(TransCtx *t, const char *st, const char *kind, Addr line, uint64_t seq,
      Addr pc, Addr victim, uint64_t cause, uint64_t sq, uint64_t id,
      const Kv &kv)
{
    if (!t)
        return emit(st, kind, line, seq, pc, victim, cause, sq, id, kv);
    Kv k2 = kv;
    k2.str("ev", t->event).str("st", t->state);
    t->pending.push_back(
        format(st, kind, line, seq, pc, victim, cause, sq, id, k2));
    return id;
}

void
flush(TransCtx &t, const std::string &nst)
{
    for (auto &l : t.pending)
        printLine(l + ":nst=" + nst);
    t.pending.clear();
}

bool
isDemandEvent(const std::string &machine, const std::string &ev)
{
    if (machine == "L1Cache")
        return ev == "Load" || ev == "Ifetch" || ev == "Store" ||
               ev == "SpecLoad" || ev == "Expose";
    if (machine == "L2Cache")
        return startsWith(ev, "L1_GET") || ev == "L1_UPGRADE" ||
               ev == "L1_EXPOSE";
    return false;
}

template <class C>
auto rollbackAddrImpl(C *cm, Addr a, int ct, int)
    -> decltype(cm->cleanup_get_rollback_addr(a, ct))
{
    return cm->cleanup_get_rollback_addr(a, ct);
}

template <class C>
Addr rollbackAddrImpl(C *, Addr, int, long)
{
    return NONE;
}

template <class R>
auto ctIdImpl(const R *m, int) -> decltype((int)m->m_ct_id)
{
    return m->m_ct_id;
}

template <class R>
int ctIdImpl(const R *, long)
{
    return -1;
}

}

std::string
reqOfRubyType(const std::string &t, bool validate)
{
    if (t == "LD" || t == "Load_Linked" || t == "RMW_Read" ||
        t == "Locked_RMW_Read")
        return "ld";
    if (t == "ST" || t == "ATOMIC" || t == "Store_Conditional" ||
        t == "RMW_Write" || t == "Locked_RMW_Write")
        return "st";
    if (t == "IFETCH")
        return "ifetch";
    if (t == "SPEC_LD")
        return "specld";
    if (t == "EXPOSE")
        return validate ? "validate" : "expose";
    if (startsWith(t, "CLEANUP"))
        return "cleanup";
    if (t == "FLUSH")
        return "flush";
    return "-";
}

void
noteRubyRequest(const RubyRequest *m)
{
    MsgCtx c;
    c.valid = true;
    c.isCpu = true;
    c.line = lineOf(m->m_LineAddress);
    c.isIfetch = (m->m_Type == RubyRequestType_IFETCH);
    c.pc = m->m_ProgramCounter ? m->m_ProgramCounter : NONE;
    c.addr = m->m_PhysicalAddress;
    c.size = m->m_Size;
    c.ptr = (const void *)m;
    c.msg = RubyRequestType_to_string(m->m_Type);
    c.ctId = ctIdImpl(m, 0);
    bool validate = false;
    if (m->m_pkt && m->m_pkt->req && m->m_pkt->req->hasInstSeqNum())
        c.seq = m->m_pkt->req->getReqInstSeqNum();
    if (m->m_pkt)
        validate = m->m_pkt->isValidate();
    c.req = reqOfRubyType(c.msg, validate);
    g_msg = c;
}

void
noteMsgAddr(Addr a, const std::string &type, const void *ptr)
{
    MsgCtx c;
    c.valid = true;
    c.line = lineOf(a);
    c.msg = type;
    c.ptr = ptr;
    c.req = "coh";
    g_msg = c;
}

void
beginTransition(const char *machine, int version, const std::string &event,
                const std::string &state, const std::string &statePerm,
                Addr addr)
{
    TransCtx t;
    t.machine = machine;
    t.version = version;
    t.event = event;
    t.state = state;
    t.statePerm = statePerm;
    t.addr = addr;
    t.allocated = false;
    t.deallocated = false;
    t.tbeAlloc = false;
    t.hmId = NONE;
    if (isDemandEvent(t.machine, event) &&
        (t.machine != "L1Cache" || (g_msg.valid && g_msg.isCpu)))
        t.hmId = newId();
    g_trans.push_back(t);
    LineKey k = keyFor(&t, addr);
    if (statePerm != "Busy" && g_lastStable.find(k) == g_lastStable.end())
        g_lastStable[k] = std::make_pair(state, isPresentPerm(statePerm));
}

void
abortTransition()
{
    if (g_trans.empty())
        return;
    TransCtx t = g_trans.back();
    g_trans.pop_back();
    flush(t, "?");
}

void
endTransition(bool valid, const std::string &nextState,
              const std::string &nextPerm)
{
    if (g_trans.empty())
        return;
    TransCtx t = g_trans.back();
    g_trans.pop_back();
    if (!valid) {
        flush(t, "-");
        return;
    }

    uint64_t seq, pc;
    std::string req;
    attr(seq, pc, req);
    Addr line = lineOf(t.addr);
    const std::string &ev = t.event;
    std::string st = machineStruct(&t);

    if (t.hmId != NONE) {
        bool miss = t.tbeAlloc || !isPresentPerm(t.statePerm);
        std::string hst = st;
        if (t.machine == "L1Cache")
            hst = (g_msg.valid && g_msg.isIfetch) ? "L1I" : "L1D";
        uint64_t id = t.hmId;
        Kv kv = ctxKv(req);
        kv.str("ev", ev).str("st", t.state).str("nst", nextState);
        if (t.machine == "L2Cache")
            kv.str("lvl", "L2");
        else
            kv.str("lvl", miss ? "-" : "L1");
        emit(hst.c_str(), miss ? "miss" : "hit", line, seq, pc, NONE, NONE,
             NONE, id, kv);
    }

    flush(t, nextState);

    if (t.machine == "L1Cache" && g_msg.valid && g_msg.isCpu &&
        isDemandEvent(t.machine, ev) && t.tbeAlloc && !t.allocated)
        dropFill(st, line);

    const char *kind = nullptr;
    std::string why;
    if (ev == "Skip_ROLLBACK" || ev == "Skip_Inflight_Cleanup") {
        kind = "cleanup_skip";
    } else if (ev == "Load_ROLLBACK" && !t.allocated &&
               isPresentPerm(t.statePerm)) {
        kind = "cleanup_skip";
        why = "present";
    } else if (ev == "Inv_CLEANUP" && !t.deallocated &&
               t.statePerm != "Busy") {
        kind = "cleanup_skip";
    } else if (ev == "Inflight_CLEANUP_reqs") {
        if (t.state == "NP")
            kind = "cleanup_drop";
        else if (nextState == "NP")
            kind = "cleanup_skip";
    } else if (ev == "Drop_Load_Cleanup_Inflight") {
        kind = "cleanup_drop";
    } else if (startsWith(ev, "DropIncomingPacket")) {
        kind = "cleanup_drop_data";
    } else if (ev == "SendAck_Cleanup_Invalidate") {
        if (nextState != t.state) {
            kind = "cleanup_skip";
            why = "ack_no_inv";
        } else if (g_waitSeen.insert(std::make_pair(g_msg.ptr, line))
                       .second) {
            kind = "cleanup_wait";
        }
    }
    if (kind) {
        Kv kv = ctxKv(req);
        if (!why.empty())
            kv.str("why", why);
        kv.str("ev", ev).str("st", t.state).str("nst", nextState);
        emit(st.c_str(), kind, line, seq, pc, NONE, NONE, sqForInst(seq),
             NONE, kv);
    }

    if (nextPerm != "Busy") {
        LineKey k = keyFor(&t, t.addr);
        bool nowPresent = isPresentPerm(nextPerm);
        auto it = g_lastStable.find(k);
        if (it != g_lastStable.end() && it->second.first != nextState &&
            it->second.second && nowPresent && !t.allocated &&
            !t.deallocated) {
            Kv kv = ctxKv(req);
            kv.str("ev", ev).str("st", t.state).str("nst", nextState)
              .str("pst", it->second.first);
            emit(st.c_str(), "coh", line, seq, pc, NONE, NONE, NONE, NONE,
                 kv);
        }
        g_lastStable[k] = std::make_pair(nextState, nowPresent);
    }
}

void
onCacheAllocate(CacheMemory *cm, Addr a, int64_t set, int way)
{
    if (!enabled())
        return;
    TransCtx *t = cur();
    const std::string &st = structOf(cm);
    uint64_t seq, pc;
    std::string req;
    attr(seq, pc, req);
    Addr line = lineOf(a);
    Kv kv = ctxKv(req);
    kv.sdec("set", set).sdec("way", way);
    if (t && contains(t->event, "ROLLBACK")) {
        uint64_t sq = sqForInst(seq);
        rEmit(t, st.c_str(), "cleanup_restore_req", line, seq, pc, NONE,
              NONE, sq, NONE, kv);
        g_rollback[keyFor(t, line)] = std::make_tuple(seq, pc, sq);
    } else {
        uint64_t id = takeFill(st, line, seq);
        rEmit(t, st.c_str(), "fill", line, seq, pc, NONE, NONE, NONE, id,
              kv);
    }
    if (t) {
        t->allocated = true;
        g_resident[keyFor(t, line)] = st;
    }
}

void
onCacheDeallocate(CacheMemory *cm, Addr a, int64_t set, int way)
{
    if (!enabled())
        return;
    TransCtx *t = cur();
    const std::string &st = structOf(cm);
    uint64_t seq, pc;
    std::string req;
    attr(seq, pc, req);
    Addr line = lineOf(a);
    std::string ev = t ? t->event : std::string();
    Kv kv;
    if (contains(ev, "Replacement")) {
        bool cpu = g_msg.valid && g_msg.isCpu;
        if (cpu && g_msg.req == "cleanup") {
            Addr rb = NONE;
            if (g_msg.ctId >= 0)
                rb = rollbackAddrImpl(cm, g_msg.line, g_msg.ctId, 0);
            Addr incoming = (rb != NONE) ? lineOf(rb) : NONE;
            uint64_t cause = (incoming != NONE)
                ? reserveFill(st, incoming, seq) : NONE;
            kv = ctxKv("rollback");
            kv.sdec("set", set).sdec("way", way)
              .hex("cln", g_msg.line);
            rEmit(t, st.c_str(), "evict", incoming, seq, pc, line, cause,
                  sqForInst(seq), NONE, kv);
            if (seq != NONE) {
                setLineAttr(line, seq, pc);
                g_lineReq[line] = "wb";
            }
        } else if (cpu && g_msg.line == line) {
            kv = ctxKv(req);
            kv.sdec("set", set).sdec("way", way).str("why", "clusivity");
            rEmit(t, st.c_str(), "inv", line, seq, pc, NONE, NONE, NONE,
                  NONE, kv);
        } else {
            Addr incoming = (g_msg.valid && g_msg.line != line)
                ? g_msg.line : line;
            uint64_t cause = (incoming != line)
                ? reserveFill(st, incoming, seq) : NONE;
            kv = ctxKv(req);
            kv.sdec("set", set).sdec("way", way);
            rEmit(t, st.c_str(), "evict", incoming, seq, pc, line, cause,
                  NONE, NONE, kv);
            if (seq != NONE) {
                setLineAttr(line, seq, pc);
                g_lineReq[line] = "wb";
            }
        }
    } else if (ev == "Inv_CLEANUP" || ev == "Cleanup_Invalidate" ||
               ev == "Cleanup_Invalidate_clean") {
        kv = ctxKv(req);
        kv.sdec("set", set).sdec("way", way);
        rEmit(t, st.c_str(), "cleanup_inv", line, seq, pc, NONE, NONE,
              sqForInst(seq), NONE, kv);
    } else {
        kv = ctxKv(req);
        kv.sdec("set", set).sdec("way", way);
        rEmit(t, st.c_str(), "inv", line, seq, pc, NONE, NONE, NONE, NONE,
              kv);
    }
    if (t) {
        t->deallocated = true;
        g_resident.erase(keyFor(t, line));
    }
}

void
onCacheTouch(CacheMemory *cm, Addr a, int64_t set, int way)
{
    if (!enabled())
        return;
    uint64_t seq, pc;
    std::string req;
    attr(seq, pc, req);
    Kv kv = ctxKv(req);
    kv.sdec("set", set).sdec("way", way);
    rEmit(cur(), structOf(cm).c_str(), "repl_touch", lineOf(a), seq, pc,
          NONE, NONE, NONE, NONE, kv);
}

namespace {

const char *
tbeStruct(const TransCtx *t)
{
    if (!t) return "TBE";
    if (t->machine == "L1Cache") return "MSHR";
    if (t->machine == "L2Cache") return "L2MSHR";
    if (t->machine == "Directory") return "DIRTBE";
    return "TBE";
}

std::map<LineKey, std::tuple<uint64_t, Addr, std::string> > g_tbe;

}

void
onTBEAllocate(Addr a)
{
    if (!enabled())
        return;
    Addr line = lineOf(a);
    if (g_msg.valid) {
        if (g_msg.isCpu) {
            setLineAttr(line, g_msg.seq, g_msg.pc);
            g_lineReq[line] = g_msg.req;
        } else if (g_msg.line != line) {
            uint64_t seq, pc;
            if (getLineAttr(g_msg.line, seq, pc)) {
                setLineAttr(line, seq, pc);
                g_lineReq[line] = lineReq(g_msg.line);
            }
        }
    }
    TransCtx *t = cur();
    if (t)
        t->tbeAlloc = true;
    uint64_t seq, pc;
    std::string req;
    attr(seq, pc, req);
    if (seq == NONE) {
        getLineAttr(line, seq, pc);
        req = lineReq(line);
    }
    g_tbe[keyFor(t, line)] = std::make_tuple(seq, pc, req);
    rEmit(t, tbeStruct(t), "buf_fill", line, seq, pc, NONE, NONE, NONE,
          NONE, ctxKv(req));
}

void
onTBEDeallocate(Addr a)
{
    if (!enabled())
        return;
    TransCtx *t = cur();
    Addr line = lineOf(a);
    uint64_t seq = NONE, pc = NONE;
    std::string req = "-";
    auto it = g_tbe.find(keyFor(t, line));
    if (it != g_tbe.end()) {
        seq = std::get<0>(it->second);
        pc = std::get<1>(it->second);
        req = std::get<2>(it->second);
        g_tbe.erase(it);
    }
    Kv kv;
    kv.str("req", req);
    rEmit(t, tbeStruct(t), "buf_release", line, seq, pc, NONE, NONE, NONE,
          NONE, kv);
    auto rb = g_rollback.find(keyFor(t, line));
    if (rb != g_rollback.end()) {
        Kv k2;
        k2.str("req", "rollback");
        rEmit(t, "L1D", "cleanup_restore", line, std::get<0>(rb->second),
              std::get<1>(rb->second), NONE, NONE, std::get<2>(rb->second),
              NONE, k2);
        g_rollback.erase(rb);
    }
}

}
