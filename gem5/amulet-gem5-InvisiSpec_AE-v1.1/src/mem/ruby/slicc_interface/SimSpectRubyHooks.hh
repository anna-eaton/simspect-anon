
#ifndef __MEM_RUBY_SLICC_INTERFACE_SIMSPECTRUBYHOOKS_HH__
#define __MEM_RUBY_SLICC_INTERFACE_SIMSPECTRUBYHOOKS_HH__

#include <sstream>
#include <string>
#include <utility>

#include "base/types.hh"
#include "sim/simspect_hooks.hh"

class RubyRequest;
class CacheMemory;

namespace SimSpect {

struct MsgCtx
{
    bool valid;
    Addr line;
    bool isCpu;
    bool isIfetch;
    uint64_t seq;
    Addr pc;
    Addr addr;
    uint64_t size;
    std::string req;
    std::string msg;
    int ctId;
    const void *ptr;
    MsgCtx() : valid(false), line(0), isCpu(false), isIfetch(false),
               seq(NONE), pc(NONE), addr(NONE), size(NONE), req("-"),
               msg("-"), ctId(-1), ptr(nullptr) {}
};
extern MsgCtx g_msg;

void noteRubyRequest(const RubyRequest *m);
void noteMsgAddr(Addr a, const std::string &type, const void *ptr);

template <class T>
auto msgTypeStr(const T *m, int) -> decltype(
    std::declval<std::ostream &>() << m->m_Type, std::string())
{
    std::ostringstream os;
    os << m->m_Type;
    return os.str();
}

template <class T>
std::string msgTypeStr(const T *, long)
{
    return "-";
}

template <class T>
auto noteMsgImpl(const T *m, int) -> decltype((void)m->m_addr, void())
{
    noteMsgAddr(m->m_addr, msgTypeStr(m, 0), (const void *)m);
}

template <class T>
void noteMsgImpl(const T *, long)
{
    g_msg = MsgCtx();
}

template <class T>
inline void noteMsg(const T *m)
{
    if (enabled())
        noteMsgImpl(m, 0);
}

inline void noteMsg(const RubyRequest *m)
{
    if (enabled())
        noteRubyRequest(m);
}

class MsgScope
{
    MsgCtx saved;
    bool on;
  public:
    template <class T>
    explicit MsgScope(const T *m) : on(enabled())
    {
        if (on) {
            saved = g_msg;
            noteMsg(m);
        }
    }
    ~MsgScope() { if (on) g_msg = saved; }
};

void beginTransition(const char *machine, int version,
                     const std::string &event, const std::string &state,
                     const std::string &statePerm, Addr addr);
void endTransition(bool valid, const std::string &nextState,
                   const std::string &nextPerm);
void abortTransition();

class TransGuard
{
    bool on;
  public:
    explicit TransGuard(bool o) : on(o) {}
    void done() { on = false; }
    ~TransGuard() { if (on) abortTransition(); }
};

void onCacheAllocate(CacheMemory *cm, Addr a, int64_t set, int way);
void onCacheDeallocate(CacheMemory *cm, Addr a, int64_t set, int way);
void onCacheTouch(CacheMemory *cm, Addr a, int64_t set, int way);

void onTBEAllocate(Addr a);
void onTBEDeallocate(Addr a);

std::string reqOfRubyType(const std::string &t, bool validate);

}

#endif
