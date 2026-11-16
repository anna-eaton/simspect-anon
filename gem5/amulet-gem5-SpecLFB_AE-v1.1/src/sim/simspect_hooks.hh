
#ifndef __SIM_SIMSPECT_HOOKS_HH__
#define __SIM_SIMSPECT_HOOKS_HH__

#include <cstdint>
#include <string>

#include "base/types.hh"

namespace gem5 {
namespace SimSpect {

static const uint64_t NONE = ~0ULL;

bool enabled();

inline Addr lineOf(Addr a) { return a & ~Addr(63); }

uint64_t newId();

struct Kv
{
    std::string s;
    Kv &str(const char *k, const std::string &v);
    Kv &hex(const char *k, uint64_t v);
    Kv &dec(const char *k, uint64_t v);
    Kv &sdec(const char *k, int64_t v);
    Kv &flag(const char *k, bool v) { return dec(k, v ? 1 : 0); }
    Kv &raw(const std::string &already_formatted) { s += already_formatted; return *this; }
};

std::string format(const char *st, const char *kind, Addr line, uint64_t seq,
                   Addr pc, Addr victim, uint64_t cause, uint64_t sq,
                   uint64_t &id, const Kv &kv = Kv());
void printLine(const std::string &l);

uint64_t emit(const char *st, const char *kind, Addr line, uint64_t seq,
              Addr pc, Addr victim, uint64_t cause, uint64_t sq,
              uint64_t id = NONE, const Kv &kv = Kv());

uint64_t noteSquash(uint64_t squashSeq, Addr pc);
uint64_t sqForInst(uint64_t seq);
uint64_t sqForSquashSeq(uint64_t squashSeq);
uint64_t sqExact(uint64_t squashSeq);

void setLineAttr(Addr line, uint64_t seq, Addr pc);
bool getLineAttr(Addr line, uint64_t &seq, Addr &pc);

uint64_t reserveFill(const std::string &st, Addr line, uint64_t seq);
uint64_t takeFill(const std::string &st, Addr line, uint64_t seq);
bool dropFill(const std::string &st, Addr line);

void setTlbCtx(uint64_t seq, Addr pc);
void getTlbCtx(uint64_t &seq, Addr &pc);

void notePktLvl(const void *pkt, const char *lvl);
std::string takePktLvl(const void *pkt);

void tagSet(const char *tag, uint64_t a, uint64_t b);
bool tagHas(const char *tag, uint64_t a, uint64_t b);
bool tagErase(const char *tag, uint64_t a, uint64_t b);

}
}

#endif
