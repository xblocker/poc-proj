#ifndef LAVA_ASSEMBER_H
#define LAVA_ASSEMBER_H

#include <config/bitcoin-config.h>
#include <pubkey.h>
#include <key.h>
#include <chain.h>

class CPOCBlockAssember
{
public:
    CPOCBlockAssember();

    ~CPOCBlockAssember() = default;

    bool UpdateDeadline(const int height, const CKeyID& gen_to, const uint64_t plot_id, const uint64_t nonce, uint64_t& deadline, const CKey& key);

    void CreateNewBlock();

    void SetNull();

    void SetFirestoneAt(const CKey& sourceKey);

    void CheckDeadline();

private:
    uint256       genSig;
    int           height;
    CKeyID        gento;
    uint64_t      plotId;
    uint64_t      nonce;
    uint64_t      deadline;
    uint64_t      dl;
    CKey          key;
    CKey          firestoneKey;
    boost::mutex  mtx;
};

#endif // BITCOIN_ASSEMBER_H
