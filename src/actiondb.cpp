#include <actiondb.h>
#include <validation.h>
#include <chainparams.h>
#include <logging.h>
#include <crypto/curve25519.h>

CAction MakeBindAction(const CKeyID& from, const CKeyID& to)
{
    CBindAction ba(std::make_pair(from, to));
    return std::move(CAction(ba));
}

static bool Sign(unsigned char privateKey[32], const unsigned char data[32], unsigned char signature[64], unsigned char publicKey[32])
{
    uint8_t signingKey[32] = {0};
    crypto::curve25519_kengen(publicKey, signingKey, privateKey);

    unsigned char x[32], Y[32], h[32], v[32];
    CSHA256().Write(data, 32).Write(signingKey, 32).Finalize(x); // digest(m + s) => x
    crypto::curve25519_kengen(Y, NULL, x); // keygen(Y, NULL, x) => Y
    CSHA256().Write(data, 32).Write(Y, 32).Finalize(h); // digest(m + Y) => h
    int r = crypto::curve25519_sign(v, h, x, signingKey); // sign(v, h, x, s)
    if (r == 1) {
        memcpy(signature, v, 32);
        memcpy(signature + 32, h, 32);
        return true;
    } else
        return false;
}

bool SignAction(const COutPoint out, const CAction &action, const CKey& key, std::vector<unsigned char>& vch)
{
    std::vector<unsigned char> vchSig(64);
    std::vector<unsigned char> vchPubkey(32);
    auto actionVch = SerializeAction(action);
    
    vch.clear();
    vch.insert(vch.end(), actionVch.begin(), actionVch.end());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << actionVch << out;
    auto hash = ss.GetHash();

    if(!Sign((unsigned char*)key.begin(), hash.begin(), vchSig.data(), vchPubkey.data()))
        return false;
    vch.insert(vch.end(), vchPubkey.begin(), vchPubkey.end());
    vch.insert(vch.end(), vchSig.begin(), vchSig.end());
    return true;
}

static bool Verify(const unsigned char publicKey[32], const unsigned char data[32], const unsigned char signature[64])
{
    unsigned char Y[32], h[32];
    crypto::curve25519_verify(Y, signature, signature + 32, publicKey); // verify25519(Y, signature, signature + 32, P) => Y
    CSHA256().Write(data, 32).Write(Y, 32).Finalize(h); // digest(m + Y) => h
    return memcmp(h, signature + 32, 32) == 0;
}

bool VerifyAction(const COutPoint out, const CAction& action, std::vector<unsigned char>& vchSig)
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << SerializeAction(action) << out;

    const unsigned char* publicKey = vchSig.data();
    const unsigned char* signature = vchSig.data() + 32;
    auto hash = ss.GetHash();
    const unsigned char* data = hash.begin();
    
    if (!Verify(publicKey, data, signature))
        return false;

    auto result{ false };
    if (action.type() == typeid(CBindAction)) {
        auto from = boost::get<CBindAction>(action).first;
        result = from.GetPlotID() == poc::ToPlotId(publicKey);
    } else if (action.type() == typeid(CUnbindAction)) {
        auto from = boost::get<CUnbindAction>(action);
        result = from.GetPlotID() == poc::ToPlotId(publicKey);
    }
    return result;
}

std::vector<unsigned char> SerializeAction(const CAction& action) {
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << action.which();
    boost::apply_visitor(CActionVisitor(&ss), action);
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CAction UnserializeAction(const std::vector<unsigned char>& vch) {
    CDataStream ss(vch, SER_GETHASH, PROTOCOL_VERSION);
    int ty = 0;
    ss >> ty;
    switch (ty) {
    case 1:
    {
        CBindAction ba;
        ss >> ba;
        return std::move(CAction(ba));
    }
    case 2:
    {
        CUnbindAction uba;
        ss >> uba;
        return std::move(CAction(uba));
    }
    }
    return std::move(CAction(CNilAction{}));
}

CAction DecodeAction(const CTransactionRef tx, std::vector<unsigned char>& vchSig)
{
    do {
        if (tx->IsCoinBase() || tx->IsNull() || tx->vout.size() != 2 
            || (tx->vout[0].nValue != 0 && tx->vout[1].nValue != 0)) 
            continue;

        CAmount nAmount{ 0 };
        for (auto vin : tx->vin) {
            auto coin = pcoinsTip->AccessCoin(vin.prevout);
            nAmount += coin.out.nValue;
        }
        auto outValue = tx->GetValueOut();
        if (nAmount - outValue != Params().GetConsensus().nActionFee) {
            LogPrintf("Action warning fees, fee=%u\n", nAmount - outValue);
            continue;
        }
        for (auto vout : tx->vout) {
            if (vout.nValue != 0) continue;
            auto script = vout.scriptPubKey;
            CScriptBase::const_iterator pc = script.begin();
            opcodetype opcodeRet;
            std::vector<unsigned char> vchRet;
            if (!script.GetOp(pc, opcodeRet, vchRet) || opcodeRet != OP_RETURN) {
                continue;
            }
            script.GetOp(pc, opcodeRet, vchRet);
            auto action = UnserializeAction(vchRet);
            if (vchRet.size() < (64+32)) continue;
            vchSig.clear();
            vchSig.insert(vchSig.end(), vchRet.end() - (64+32), vchRet.end());
            return std::move(action);
        }
    } while (false);
    return CAction(CNilAction{});
}


static const char DB_ACTIVE_ACTION_KEY = 'K';
static const char DB_RELATIONID = 'P';

CRelationView::CRelationView(size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(GetDataDir() / "action" / "relation", nCacheSize, fMemory, fWipe) 
{
}

CKeyID CRelationView::To(const CKeyID& from) const
{
    auto to = To(from.GetPlotID());
    return std::move(to);
}

CKeyID CRelationView::To(uint64_t plotid) const
{
    CKeyID value;
    auto key = relationTip.find(plotid);
    if(key!=relationTip.end()){
        auto to_key = std::make_pair(DB_RELATIONID, key->second);
        if(!Read(to_key, value)){
            LogPrint(BCLog::RELATION, "CRelationView::To failure, can not get to plotid, from:%u\n", plotid);
        }
    }else{
        LogPrint(BCLog::RELATION, "CRelationView::To failure, get bind to, from:%u\n", plotid);
    }
    return std::move(value);
}

bool CRelationView::AcceptAction(const int height, const uint256& txid, const CAction& action, std::vector<std::pair<uint256, CRelationActive>>& relations)
{
    CDBBatch batch(*this);
    LogPrintf("AcceptAction, tx:%s\n", txid.GetHex());
    if (action.type() == typeid(CBindAction)) {
        auto ba = boost::get<CBindAction>(action);
        auto from = ba.first;
        auto to = ba.second;
        auto active = std::make_pair(txid, std::make_pair(from, to));
        relations.push_back(active);
        // write plotID and CKeyID into disk.
        batch.Write(std::make_pair(DB_RELATIONID, ba.first.GetPlotID()), ba.first);
        batch.Write(std::make_pair(DB_RELATIONID, ba.second.GetPlotID()), ba.second);
        // add new action at tip
        relationTip[ba.first.GetPlotID()] = ba.second.GetPlotID();
        LogPrintf("bind action, from:%u, to:%u\n", from.GetPlotID(), ba.second.GetPlotID());
    } else if (action.type() == typeid(CUnbindAction)) {
        auto from = boost::get<CUnbindAction>(action);
        auto active = std::make_pair(txid,std::make_pair(from, CKeyID()));
        relations.push_back(active);
        LogPrintf("unbind action, from:%u\n", from.GetPlotID());
        auto key = relationTip.find(from.GetPlotID());
        if(key!=relationTip.end()){
            relationTip.erase(key);
        }
    }
    return WriteBatch(batch);
}

void CRelationView::ConnectBlock(const int height, const CBlock &blk){
    //get tip relation map
    if (height > 0){
        relationTip = relationMapIndex[height-1];
    }

    std::vector<std::pair<uint256, CRelationActive>> relations;
    //accept action
    for (auto tx: blk.vtx) {
        std::vector<unsigned char> vchSig;
        auto action = DecodeAction(tx, vchSig);
        if (action.type() != typeid(CNilAction)) {
            LogPrintf("DecodeAction not nil action: %s\n", tx->GetHash().GetHex());
            auto out = tx->vin[0].prevout;
            if (VerifyAction(out, action, vchSig)) {
                if (!AcceptAction(height, tx->GetHash(), action, relations)) {
                    LogPrintf("AcceptAction failure: %s\n", tx->GetHash().GetHex());
                }
            }
            else {
                LogPrintf("VerifyAction failure: %s\n", tx->GetHash().GetHex());
            }
        }
    }
    relationMapIndex[height] = relationTip;

    if (relations.size() > 0) {
        if (!WriteRelationsToDisk(height, relations)) {
            LogPrint(BCLog::RELATION, "%s: WriteRelationToDisk retrun false, height:%d\n", __func__, height);
        }
    }

}

bool CRelationView::WriteRelationsToDisk(const int height, const std::vector<std::pair<uint256, CRelationActive>>& relations)
{
    return Write(std::make_pair(DB_ACTIVE_ACTION_KEY, height), relations);
}


void CRelationView::DisconnectBlock(const int height, const CBlock &blk)
{
    // erase disk
    LogPrint(BCLog::RELATION, "%s: height:%d, block:%s\n", __func__, height, blk.GetHash().ToString());
    auto key = std::make_pair(DB_ACTIVE_ACTION_KEY, height);
    Erase(key, true);

    // reset tip relation
    relationTip = relationMapIndex[height-1];

    // erase tip at height
    auto relationkey = relationMapIndex.find(height);
    if(relationkey!=relationMapIndex.end()){
        relationMapIndex.erase(relationkey);
    }
}

bool CRelationView::LoadRelationFromDisk(const int height)
{
    auto key = std::make_pair(DB_ACTIVE_ACTION_KEY, height);
    if (Exists(key)) {
        std::vector<std::pair<uint256, CRelationActive>> relations;
        if (!Read(key, relations)) {
            LogPrint(BCLog::RELATION, "%s: Read retrun false, height:%d\n", __func__, height);
            return false;
        }
        for (auto relation : relations) {
            if (relation.second.second != CKeyID()) {
                auto from = relation.second.first;
                auto to   = relation.second.second;
                relationTip[from.GetPlotID()] = to.GetPlotID();
                LogPrintf("bind action, from:%u, to:%u\n", from.GetPlotID(), to.GetPlotID());
            } else if (relation.second.second == CKeyID()) {
                auto from = relation.second.first;
                LogPrintf("unbind action, from:%u\n", from.GetPlotID());
                auto key = relationTip.find(from.GetPlotID());
                if(key!=relationTip.end()){
                    relationTip.erase(key);
                }
            }
        }
    }
    relationMapIndex[height] = relationTip;
    return true;
}

CRelationVector CRelationView::ListRelations() const
{
    CRelationVector vch;
    for (auto iter = relationTip.begin(); iter != relationTip.end(); iter++ ) {
        auto fromPlotid = iter->first;
        auto from_key = std::make_pair(DB_RELATIONID, fromPlotid);
        CKeyID from;
        if(!Read(from_key, from)){
            LogPrint(BCLog::RELATION, "%s: Read KeyID retrun false, PlotID:%u\n", __func__, fromPlotid);
            continue;
        }
        auto toPlotid = iter->second;
        auto to_key = std::make_pair(DB_RELATIONID, toPlotid);
        CKeyID to;
        if(!Read(to_key, to)){
            LogPrint(BCLog::RELATION, "%s: Read KeyID retrun false, PlotID:%u\n", __func__, toPlotid);
            continue;
        }
        auto value = std::make_pair(from, to);
        vch.push_back(value);
    }
    return std::move(vch);
}