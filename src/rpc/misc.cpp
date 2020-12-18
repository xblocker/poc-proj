// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <key_io.h>
#include <validation.h>
#include <httpserver.h>
#include <net.h>
#include <netbase.h>
#include <outputtype.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <timedata.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <warnings.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>
#include <support/events.h>

#include <util/client_http.hpp>
#include <util/client_https.hpp>
#include <util/crypto.hpp>
#include <util/status_code.hpp>
#include <util/utility.hpp>

#include <stdint.h>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>

static UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"validateaddress",
                "\nReturn information about the given bitcoin address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to validate"},
                },
                RPCResult{
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\",        (string) The bitcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex-encoded scriptPubKey generated by the address\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"iswitness\" : true|false,     (boolean) If the address is a witness address\n"
            "  \"witness_version\" : version   (numeric, optional) The version number of the witness program\n"
            "  \"witness_program\" : \"hex\"     (string, optional) The hex value of the witness program\n"
            "}\n"
                },
                RPCExamples{
                    HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
                },
            }.ToString());

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("isvalid", isValid);
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

        UniValue detail = DescribeAddress(dest);
        ret.pushKVs(detail);
    }
    return ret;
}

static UniValue createmultisig(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        std::string msg =
            RPCHelpMan{"createmultisig",
                "\nCreates a multi-signature address with n signature of m keys required.\n"
                "It returns a json object with the address and redeemScript.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of required signatures out of the n keys."},
                    {"keys", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of hex-encoded public keys.",
                        {
                            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded public key"},
                        }},
                    {"address_type", RPCArg::Type::STR, /* default */ "legacy", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"
                },
                RPCExamples{
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
                },
            }.ToString();
        throw std::runtime_error(msg);
    }

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\n.", keys[i].get_str()));
        }
    }

    // Get the output type
    OutputType output_type = OutputType::LEGACY;
    if (!request.params[2].isNull()) {
        if (!ParseOutputType(request.params[2].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[2].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    const CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    CBasicKeyStore keystore;
    const CTxDestination dest = AddAndGetDestinationForScript(keystore, inner, output_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));

    return result;
}

UniValue createhtlcaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4) {
        std::string msg = "createhtlcaddress seller_key refund_key hash timeout_type lockheight\n"
            "\nCreates an address whose funds can be unlocked with a preimage or as a refund\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. seller_key    (string, required) The public key of the possessor of seller. \n"
            "2. refund_key    (string, required) The public key of the recipient of the refund.\n"
            "3. hash          (string, required) SHA256 or RIPEMD160 hash of the preimage.\n"
            "4. lockheight       (string, required) Block height of the contract (denominated in blocks) relative to its placement in the blockchain\n"

            "\nResult:"
            "{\n"
            "  \"address\":\"htlcaddress\"   (string) The value of the new HTLC address.\n"
            "  \"redeemScript\":\"script\"   (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nPay someone for the preimage of 254e38932fdb9fc27f82aac2a5cc6d789664832383e3cf3298f8c120812712db\n"
            + HelpExampleCli("createhtlcaddress", "0333ffc4d18c7b2adbd1df49f5486030b0b70449c421189c2c0f8981d0da9669af 0333ffc4d18c7b2adbd1df49f5486030b0b70449c421189c2c0f8981d0da9669af 254e38932fdb9fc27f82aac2a5cc6d789664832383e3cf3298f8c120812712db 10") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createhtlcaddress", "0333ffc4d18c7b2adbd1df49f5486030b0b70449c421189c2c0f8981d0da9669af, 0333ffc4d18c7b2adbd1df49f5486030b0b70449c421189c2c0f8981d0da9669af, 254e38932fdb9fc27f82aac2a5cc6d789664832383e3cf3298f8c120812712db, 10")
            ;

        throw std::runtime_error(msg);
    }

    CPubKey seller_key;
    CPubKey refund_key;

    CTxDestination seller_dest = DecodeDestination(request.params[0].get_str());
    CTxDestination refund_dest = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(seller_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid seller address");
    }

    if (!IsValidDestination(refund_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid refund address");
    }

    if (seller_dest.type() != typeid(CKeyID)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Seller only support PUBKEYHASH");
    }

    if (refund_dest.type() != typeid(CKeyID)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Refund only support PUBKEYHASH");
    }


    auto seller_keyID = boost::get<CKeyID>(seller_dest);
    auto refund_keyID = boost::get<CKeyID>(refund_dest);

    std::string hs = request.params[2].get_str();
    std::vector<unsigned char> image;
    opcodetype hasher;
    if (IsHex(hs)) {
        image = ParseHex(hs);

        if (image.size() == 32) {
            hasher = OP_SHA256;
        } else if (image.size() == 20) {
            hasher = OP_RIPEMD160;
        } else {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid hash image length, 32 (SHA256) and 20 (RIPEMD160) accepted");
        }
    } else {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid hash image");
    }

    uint32_t blockheight = request.params[3].get_int();
    CScript htlcscript = GetScriptForHTLC(seller_keyID, refund_keyID, image, blockheight, hasher);
    auto htlcdest = CTxDestination(CScriptID(htlcscript));

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(htlcdest));
    result.pushKV("redeemScript", HexStr(htlcscript.begin(), htlcscript.end()));
    return result;
}

UniValue getimage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
        RPCHelpMan{
            "getimage",
            "Get the SHA256 or RIPEMD160 hash of a preimage.\n"
            "This should be called before createhtlcaddress.\n",
        {
            {"preimage", RPCArg::Type::STR, RPCArg::Optional::NO, "The preimage."},
        },
        RPCResult{
            "\"preimage\"      The preimage.\n"
            "\"imagehash_SHA256\"     The imagehash.\n"
            "\"imagehash_RIPEMD160\"     The imagehash.\n"
        },
        RPCExamples{
            HelpExampleCli("getimage", "\"preimage\"")},
        }
    .ToString());

    std::vector<unsigned char> preimage = ParseHexV(request.params[0], "preimage");

    // SHA256
    std::vector<unsigned char> vch_256(32);
    {
        std::vector<unsigned char> vch(32);
        CSHA256 hash;
        hash.Write(preimage.data(), preimage.size());
        hash.Finalize(vch.data());
        vch_256 = vch;
    }

    // RIPEMD160
    std::vector<unsigned char> vch_160(20);
    {
        std::vector<unsigned char> vch(20);
        CRIPEMD160 hash;
        hash.Write(preimage.data(), preimage.size());
        hash.Finalize(vch.data());
        vch_160 = vch;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("preimage", request.params[0].get_str());
    result.pushKV("imagehash_SHA256", HexStr(vch_256.begin(),vch_256.end()));
    result.pushKV("imagehash_RIPEMD160", HexStr(vch_160.begin(),vch_160.end()));
    return result;
}

UniValue sendrawbtctx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
        RPCHelpMan{"sendrawbtctx",
        "\nSubmits raw transaction (serialized, hex-encoded) to BTC main network.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
        },
        RPCResult{
            "\"hex\"             (string) The transaction hash in hex\n"
        },
        RPCExamples{
            "\nSend the BTC transaction (signed hex)\n"
            + HelpExampleCli("sendrawbtctx", "\"signedhex\"")
        },
        }.ToString());

    RPCTypeCheck(request.params, {UniValue::VSTR});

    auto txhex = request.params[0].get_str();
    using HttpsClient = SimpleWeb::Client<SimpleWeb::HTTPS>;
    HttpsClient client("api.blockcypher.com", false);
    
    std::string txhex_str = "\"" + txhex +"\"";
    std::string json_string = "{\"tx\":" + txhex_str + "}";

    try {
        auto r2 = client.request("POST", "/v1/btc/test3/txs/push", json_string);
        return r2->content.string();
    }catch(const SimpleWeb::system_error &e) {
        e.what();
        throw JSONRPCError(RPC_TYPE_ERROR, "client req error");
    }
}

UniValue getdescriptorinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"getdescriptorinfo",
            {"\nAnalyses a descriptor.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
            },
            RPCResult{
            "{\n"
            "  \"descriptor\" : \"desc\",         (string) The descriptor in canonical form, without private keys\n"
            "  \"isrange\" : true|false,        (boolean) Whether the descriptor is ranged\n"
            "  \"issolvable\" : true|false,     (boolean) Whether the descriptor is solvable\n"
            "  \"hasprivatekeys\" : true|false, (boolean) Whether the input descriptor contained at least one private key\n"
            "}\n"
            },
            RPCExamples{
                "Analyse a descriptor\n" +
                HelpExampleCli("getdescriptorinfo", "\"wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)\"")
            }}.ToString()
        );
    }

    RPCTypeCheck(request.params, {UniValue::VSTR});

    FlatSigningProvider provider;
    auto desc = Parse(request.params[0].get_str(), provider);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor"));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("descriptor", desc->ToString());
    result.pushKV("isrange", desc->IsRange());
    result.pushKV("issolvable", desc->IsSolvable());
    result.pushKV("hasprivatekeys", provider.keys.size() > 0);
    return result;
}

UniValue deriveaddresses(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.empty() || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"deriveaddresses",
            {"\nDerives one or more addresses corresponding to an output descriptor.\n"
            "Examples of output descriptors are:\n"
            "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
            "    wpkh(<pubkey>)                       Native segwit P2PKH outputs for the given pubkey\n"
            "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
            "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
            "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
            "or more path elements separated by \"/\", where \"h\" represents a hardened child key.\n"
            "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
                {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED_NAMED_ARG, "If a ranged descriptor is used, this specifies the end or the range (in [begin,end] notation) to derive."},
            },
            RPCResult{
                "[ address ] (array) the derived addresses\n"
            },
            RPCExamples{
                "First three native segwit receive addresses\n" +
                HelpExampleCli("deriveaddresses", "\"wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#trd0mf0l\" \"[0,2]\"")
            }}.ToString()
        );
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValueType()}); // Range argument is checked later
    const std::string desc_str = request.params[0].get_str();

    int64_t range_begin = 0;
    int64_t range_end = 0;

    if (request.params.size() >= 2 && !request.params[1].isNull()) {
        auto range = ParseRange(request.params[1]);
        if (range.first < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should be greater or equal than 0");
        }
        if ((range.second >> 31) != 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "End of range is too high");
        }
        if (range.second >= range.first + 1000000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range is too large");
        }
        range_begin = range.first;
        range_end = range.second;
    }

    FlatSigningProvider provider;
    auto desc = Parse(desc_str, provider, /* require_checksum = */ true);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor"));
    }

    if (!desc->IsRange() && request.params.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
    }

    if (desc->IsRange() && request.params.size() == 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range must be specified for a ranged descriptor");
    }

    UniValue addresses(UniValue::VARR);

    for (int i = range_begin; i <= range_end; ++i) {
        std::vector<CScript> scripts;
        if (!desc->Expand(i, provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys"));
        }

        for (const CScript &script : scripts) {
            CTxDestination dest;
            if (!ExtractDestination(script, dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Descriptor does not have a corresponding address"));
            }

            addresses.push_back(EncodeDestination(dest));
        }
    }

    // This should not be possible, but an assert seems overkill:
    if (addresses.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unexpected empty result");
    }

    return addresses;
}

static UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            RPCHelpMan{"verifymessage",
                "\nVerify a signed message\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for the signature."},
                    {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature provided by the signer in base 64 encoding (see signmessage)."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
                },
                RPCResult{
            "true|false   (boolean) If the signature is verified or not.\n"
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
                },
            }.ToString());

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&destination);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == *keyID);
}

static UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            RPCHelpMan{"signmessagewithprivkey",
                "\nSign a message with the private key of an address\n",
                {
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key to sign the message with."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
                },
                RPCResult{
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
                },
                RPCExamples{
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
                },
            }.ToString());

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CKey key = DecodeSecret(strPrivkey);
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

static UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"setmocktime",
                "\nSet the local time to given timestamp (-regtest only)\n",
                {
                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString()
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

static UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"getmemoryinfo",
                "Returns an object containing information about memory usage.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "\"stats\"", "determines what kind of information is returned.\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+)."},
                },
                {
                    RPCResult{"mode \"stats\"",
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
                    },
                    RPCResult{"mode \"mallocinfo\"",
            "\"<malloc version=\"1\">...\"\n"
                    },
                },
                RPCExamples{
                    HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
                },
            }.ToString());

    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("locked", RPCLockedMemoryInfo());
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

static void EnableOrDisableLogCategories(UniValue cats, bool enable) {
    cats = cats.get_array();
    for (unsigned int i = 0; i < cats.size(); ++i) {
        std::string cat = cats[i].get_str();

        bool success;
        if (enable) {
            success = LogInstance().EnableCategory(cat);
        } else {
            success = LogInstance().DisableCategory(cat);
        }

        if (!success) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
    }
}

UniValue logging(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"logging",
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            ,
                {
                    {"include", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "A json array of categories to add debug logging",
                        {
                            {"include_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                    {"exclude", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "A json array of categories to remove debug logging",
                        {
                            {"exclude_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                },
                RPCResult{
            "{                   (json object where keys are the logging categories, and values indicates its status\n"
            "  \"category\": true|false,  (bool) if being debug logged or not. false:inactive, true:active\n"
            "  ...\n"
            "}\n"
                },
                RPCExamples{
                    HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], [\"libevent\"]")
                },
            }.ToString());
    }

    uint32_t original_log_categories = LogInstance().GetCategoryMask();
    if (request.params[0].isArray()) {
        EnableOrDisableLogCategories(request.params[0], true);
    }
    if (request.params[1].isArray()) {
        EnableOrDisableLogCategories(request.params[1], false);
    }
    uint32_t updated_log_categories = LogInstance().GetCategoryMask();
    uint32_t changed_log_categories = original_log_categories ^ updated_log_categories;

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    if (changed_log_categories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT))) {
            LogInstance().DisableCategory(BCLog::LIBEVENT);
            if (changed_log_categories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

static UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            RPCHelpMan{"echo|echojson ...",
                "\nSimply echo back the input arguments. This command is for testing.\n"
                "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in "
                "futu and the GUI. There is no server-side difference.",
                {},
                RPCResults{},
                RPCExamples{""},
            }.ToString()
        );

    return request.params;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "util",               "validateaddress",        &validateaddress,        {"address"} },
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys","address_type"} },
    { "util",               "deriveaddresses",        &deriveaddresses,        {"descriptor", "range"} },
    { "util",               "getdescriptorinfo",      &getdescriptorinfo,      {"descriptor"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },
    { "util",               "createhtlcaddress",      &createhtlcaddress,      {"seller_key","refund_key","hash","lockheight"} },
    { "util",               "sendrawbtctx",           &sendrawbtctx,           {"host","tx"} },
    { "util",               "getimage",               &getimage,               {"preimage"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
};
// clang-format on

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
