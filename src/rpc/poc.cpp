// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "poc.h"
#include "../poc.h"
#include "chainparams.h"
#include "key_io.h"
#include "keystore.h"
#include "sync.h"
#include "util.h"
#include "util/strencodings.h"
#include "wallet/coincontrol.h"
#include "wallet/wallet.h"
#include "passphrase.h"
#include <key.h>
#include <crypto/curve25519.h>

#include <algorithm>
#include <queue>
#include <wallet/rpcwallet.h>
#include <ticket.h>
#include <consensus/tx_verify.h>
#include <net.h>
#include <validation.h>

static UniValue getPlotId(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            RPCHelpMan{
                "getplotid",
                "\nGet potter id from passphrase or Generate New One.\n"
                "\nIMPORTANT!!!Save and keep your passphrase secret.\n",
                {{"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The string of the passphrase"}},
                RPCResult{
                    "{\n"
                    "  \"passphrase\": xxx, (string) The passphrase\n",
                    "  \"plotid\": nnn, (numeric) The plot id\n"
                    "}\n"},
                RPCExamples{
                    HelpExampleCli("getPlotId", "")},
            }
                .ToString());
    }
    std::string passphrase;
    if (request.params.size() > 0) {
        passphrase = request.params[0].get_str();
    } else {
        passphrase = poc::generatePassphrase();
    }
    uint64_t plotID = poc::GeneratePlotId(passphrase);
    UniValue result(UniValue::VOBJ);
    result.pushKV("passphrase", passphrase);
    result.pushKV("plotid", std::to_string(plotID));
    return result;
}

UniValue getMiningInfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{
                "getmininginfo",
                "\nReturns info for poc mining.",
                {},
                RPCResult{
                    "{\n"
                    "  \"height\": nnn\n"
                    "  \"generationSignature\": \"xxx\"\n"
                    "  \"cumulativeDiff\": \"xxx\"\n"
                    "  \"basetarget\": nnn\n"
                    "  \"targetDeadline\": nnn\n"
                    "}\n"},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "") + HelpExampleRpc("getmininginfo", "")},
            }
                .ToString());
    }
    LOCK(cs_main);

    auto height = chainActive.Height() + 1;
    auto diff = chainActive.Tip()->nCumulativeDiff;
    auto block = chainActive.Tip()->GetBlockHeader();
    auto generationSignature = CalcGenerationSignature(block.genSign, block.nPlotID);
    auto nBaseTarget = block.nBaseTarget;
    auto param = Params();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("height", height);
    obj.pushKV("generationSignature", HexStr<uint256>(generationSignature));
    obj.pushKV("cumulativeDiff", diff.GetHex());
    obj.pushKV("baseTarget", nBaseTarget);
    obj.pushKV("targetDeadline", param.TargetDeadline());
    return obj;
}

UniValue submitNonce(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5) {
        throw std::runtime_error(
            "submitNonce \"nonce\" \"plotterId\" (height \"address\" checkBind)\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) Nonce\n"
            "2. \"plotterId\"       (string, required) Plotter ID\n"
            "3. \"height\"          (integer, optional) Target height for mining\n"
            "4. \"address\"         (string, optional) Target address or private key (BHDIP007) for mining\n"
            "5. \"checkBind\"       (boolean, optional, true) Check bind for BHDIP006\n"
            "\nResult:\n"
            "{\n"
            "  [ result ]                  (string) Submit result: 'success' or others \n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "  [ height ]                  (integer, optional) Target block height\n"
            "  [ targetDeadline ]          (number) Current acceptable deadline \n"
            "}\n"
        );
    }
    
    /*if (IsInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Cannot Submit Nonce In Initial Block Download");
    }*/

    int height = 0;
    {
        LOCK(cs_main);
        height = chainActive.Height() + 1;
    }
    uint64_t nNonce = static_cast<uint64_t>(std::stoull(request.params[0].get_str()));
    uint64_t nPlotterId = static_cast<uint64_t>(std::stoull(request.params[1].get_str()));
    
    CKeyID generateTo;
    if (request.params.size() >= 4) {
        std::string strAddress = request.params[3].get_str();
        CTxDestination dest = DecodeDestination(strAddress);
        if (!IsValidDestination(dest) && dest.type() != typeid(CKeyID)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
        }
        generateTo = boost::get<CKeyID>(dest);
    }
    if (generateTo.IsNull()) {
        generateTo = prelationview->To(nPlotterId);
    }
    if (generateTo.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "PlotID not bind to any address");
    }

    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    auto wallet = wallets.size() == 1 || (request.fHelp && wallets.size() > 0) ? wallets[0] : nullptr;
    if (wallet == nullptr) {
        return NullUniValue;
    }
    CWallet* const pwallet = wallet.get();
    auto locked_chain = pwallet->chain().lock();

    CKey key;
    LOCK(pwallet->cs_wallet);
    if (!pwallet->IsLocked()) {
        pwallet->GetKey(generateTo, key);
    }
    UniValue obj(UniValue::VOBJ);
    uint64_t nDeadline;
    if (blockAssember.UpdateDeadline(height, generateTo, nPlotterId, nNonce, nDeadline, key)) {
        obj.pushKV("result", "success");
        obj.pushKV("deadline", nDeadline);
        obj.pushKV("height", height);
        auto params = Params();
        obj.pushKV("targetdeadline", params.TargetDeadline());
    } else {
        obj.pushKV("result", "error");
        obj.pushKV("errorCode", "400");
        obj.pushKV("errorDescription", "bad nonce/deadline");
    }
    return obj;
}

UniValue getslotinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{ "getslotinfo",
                "Returns an object containing fire stone slot info.\n",
                {
                    {"index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "slot index."},
                },
                RPCResult{
            "{\n"
            "  \"index\": xx,                  (numeric) the index of fire stone slot \n"
            "  \"price\": xxxxxx,              (numeric) the current price of fire stone slot\n"
            "  \"count\": xx,                  (numeric) the count of tickets in this slot\n"
            "  \"locktime\": xxxxx,            (numeric) the end of this slot\n"
            "}\n" },
                RPCExamples{
                    HelpExampleCli("getslotinfo", "") + HelpExampleCli("getslotinfo", "2")
                },
            }.ToString());
    LOCK(cs_main);
    int index = pticketview->SlotIndex();
    if (!request.params[0].isNull()) {
        index = request.params[0].get_int();
    }
    if (index < 0 || index > pticketview->SlotIndex()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid slot index");
    }
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("index", index);
    obj.pushKV("price", pticketview->TicketPriceInSlot(index));
    obj.pushKV("count", (uint64_t)pticketview->GetTicketsBySlotIndex(index).size());
    obj.pushKV("locktime", pticketview->LockTime(index));
    return obj;
}

UniValue setfsowner(const JSONRPCRequest& request){
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
        RPCHelpMan{
            "setfsowner",
            "\nset the mining fs user.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to use fs(only keyid)."},
        },
        RPCResult{
            "true|false        (boolean) Returns true if successful\n"
        },
        RPCExamples{
            HelpExampleCli("setfsowner", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\"")},
        }
    .ToString());

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid sfSource address");
    }
    if (dest.type() != typeid(CKeyID)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Only support PUBKEYHASH");
    }
    auto keyID = boost::get<CKeyID>(dest);
    CKey fsSourceKey;
    pwallet->GetKey(keyID, fsSourceKey);
    if (!fsSourceKey.IsValid()){
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "YOU HAVE NO PRIVATEKEY");
    }
    blockAssember.SetFirestoneAt(fsSourceKey);
    return true;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "hidden",            "getMiningInfo",            &getMiningInfo,          {} },
    { "poc",               "getmininginfo",            &getMiningInfo,          {} },
    { "hidden",            "submitNonce",              &submitNonce,            {"nonce", "plotterId", "height", "address", "checkBind"} },
    { "poc",               "submitnonce",              &submitNonce,            {"nonce", "plotterId", "height", "address", "checkBind"} },
	{ "poc",               "getplotid",                &getPlotId,              {"passphrase"} },
    { "poc",               "getslotinfo",              &getslotinfo,            {"index"} },
    { "wallet",            "setfsowner",               &setfsowner,             {"address"} },    
};

void RegisterPocRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
