// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>
#include <validation.h>
#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const std::vector<CScript>& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint64_t nBaseTarget, int32_t nVersion, const std::vector<CAmount>& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 2;
    txNew.vin.resize(1);
    txNew.vout.resize(3);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward[0];
    txNew.vout[0].scriptPubKey = genesisOutputScript[0];
    txNew.vout[1].nValue = genesisReward[1];
    txNew.vout[1].scriptPubKey = genesisOutputScript[1];
    txNew.vout[2].nValue = genesisReward[2];
    txNew.vout[2].scriptPubKey = genesisOutputScript[2];

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBaseTarget    = nBaseTarget;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint64_t nBaseTarget, int32_t nVersion, const std::vector<CScript>& genesisOutputScript, const std::vector<CAmount>& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBaseTarget, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 32400;
        consensus.BIP16Exception = uint256S("0xdc32ce556d0c3c08d1e770ca772cd2367b46c9b0f4151b276fbf0c7013c4ed0e");
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0xdc32ce556d0c3c08d1e770ca772cd2367b46c9b0f4151b276fbf0c7013c4ed0e");
        consensus.BIP65Height = 0; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 0; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 4 * 60;
        consensus.nPocBaseTarget = 4398046511104L;
        consensus.nPocTargetSpacing = 240;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        // TODO: better cumulative diff?
        // minimumCumulativeDiff = initialCumulativeDiff + 1
        consensus.nMinimumCumulativeDiff = ArithToUint256(arith_uint256(CUMULATIVE_DIFF_DENOM) + arith_uint256(CUMULATIVE_DIFF_DENOM / consensus.InitialBaseTarget()));

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000f1c54590ee18d15ec70e68c8cd4cfbadb1b4f11697eee"); //563378

        consensus.nActionFee = DEFAULT_TRANSACTION_MAXFEE;
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xbe;
        pchMessageStart[1] = 0xd9;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xb4;
        nDefaultPort = 5566;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        std::vector<unsigned char> scriptData0(ParseHex("a9143abb525cbf8bada26f4604f8864f69508df6ff6287"));
        std::vector<unsigned char> scriptData1(ParseHex("76a914486249861a6367be0467ab024a8619bd33de15b288ac"));
        std::vector<unsigned char> scriptData2(ParseHex("a9141065b0d7777459ce520db104777072326bf8140387"));
        std::vector<unsigned char> scriptData3(ParseHex("a914ab81044d45907dc932be5214bc497fbd5397111787"));
        std::vector<unsigned char> scriptData4(ParseHex("76a9144b03e29dfd6521f2eaeebcfad5aedaa8665ec97488ac"));
        outletScriptPubKey = CScript(scriptData3.begin(), scriptData3.end());
        stakingScriptPubKey = CScript(scriptData4.begin(), scriptData4.end());
        const std::vector<CScript> genesisOutputScript{ CScript(scriptData0.begin(), scriptData0.end()),  CScript(scriptData1.begin(), scriptData1.end()), CScript(scriptData2.begin(), scriptData2.end()) };
        const std::vector<CAmount> genesisReward = {5000000 * COIN, 50000000 * COIN, 36000000 * COIN};
        genesis = CreateGenesisBlock(1607260099, 2083236893, consensus.InitialBaseTarget(), 1, genesisOutputScript, genesisReward);
        consensus.hashGenesisBlock = genesis.GetHash();
        auto str = consensus.hashGenesisBlock.ToString();

        vFixedSeeds.clear();
        vSeeds = {
            "hk.futu.io",
            "tk.futu.io",
            "so.futu.io",
            "sp.futu.io",
        };

        // nodes with support for servicebits filtering should be at the top

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096
            /* nTime    */ 1569246923,
            /* nTxCount */ 18630,
            /* dTxRate  */ 0.0106859392924438
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;

        nSlotLength = 2048;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 65700;
        consensus.BIP16Exception = uint256S("0x62ca4ef31a124cedd557a97fd59f623ae7eff424a15a13304dd44ec2263a9b03");
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x62ca4ef31a124cedd557a97fd59f623ae7eff424a15a13304dd44ec2263a9b03");
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPocBaseTarget = 4398046511104L;
        consensus.nPocTargetSpacing = 240;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumCumulativeDiff = uint256S("0x000000000000000000000000000000000000000000000001000000003bffffff");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75"); //1354312

        pchMessageStart[0] = 0x11;
        pchMessageStart[1] = 0x07;
        pchMessageStart[2] = 0x0b;
        pchMessageStart[3] = 0x09;
        
        nDefaultPort = 5567;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 30;
        m_assumed_chain_state_size = 2;

        std::vector<unsigned char> scriptData0(ParseHex("a914e930aaf89ad5643bc1f8a2cf9de4b119f5687ac387"));
        std::vector<unsigned char> scriptData1(ParseHex("a914e930aaf89ad5643bc1f8a2cf9de4b119f5687ac387"));
        std::vector<unsigned char> scriptData2(ParseHex("a914e8e256878ccc60cdd7b6ed9be232b1c82ab25df387"));
        std::vector<unsigned char> scriptData3(ParseHex("a914ab81044d45907dc932be5214bc497fbd5397111787"));
        std::vector<unsigned char> scriptData4(ParseHex("a9149a3372632eb917d3170c81fc4595666aee144e2587"));
        outletScriptPubKey = CScript(scriptData3.begin(), scriptData3.end());
        stakingScriptPubKey = CScript(scriptData4.begin(), scriptData4.end());
        const std::vector<CScript> genesisOutputScript{ CScript(scriptData0.begin(), scriptData0.end()),  CScript(scriptData1.begin(), scriptData1.end()), CScript(scriptData2.begin(), scriptData2.end()) };
        const std::vector<CAmount> genesisReward = {5000000 * COIN, 50000000 * COIN, 36000000 * COIN};
        genesis = CreateGenesisBlock(1592638195, 414098458, consensus.InitialBaseTarget(), 1, genesisOutputScript, genesisReward);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        consensus.nActionFee = DEFAULT_TRANSACTION_MAXFEE;

        checkpointData = {
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 1531929919,
            /* nTxCount */ 19438708,
            /* dTxRate  */ 0.626
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;

        nSlotLength = 2048 / 8 / 2;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.nPocBaseTarget = 4398046511104L;
        consensus.nPocTargetSpacing = 2;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumCumulativeDiff = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nActionFee = DEFAULT_TRANSACTION_MAXFEE;

        pchMessageStart[0] = 0xb5;
        pchMessageStart[1] = 0xfa;
        pchMessageStart[2] = 0xda;
        pchMessageStart[3] = 0xbf;
        nDefaultPort = 5568;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        std::vector<unsigned char> scriptData0(ParseHex("a914e930aaf89ad5643bc1f8a2cf9de4b119f5687ac387"));
        std::vector<unsigned char> scriptData1(ParseHex("a914e930aaf89ad5643bc1f8a2cf9de4b119f5687ac387"));
        std::vector<unsigned char> scriptData2(ParseHex("a914e8e256878ccc60cdd7b6ed9be232b1c82ab25df387"));
        std::vector<unsigned char> scriptData3(ParseHex("a914ab81044d45907dc932be5214bc497fbd5397111787"));
        std::vector<unsigned char> scriptData4(ParseHex("a9149a3372632eb917d3170c81fc4595666aee144e2587"));
        outletScriptPubKey = CScript(scriptData3.begin(), scriptData3.end());
        stakingScriptPubKey = CScript(scriptData4.begin(), scriptData4.end());
        const std::vector<CScript> genesisOutputScript{ CScript(scriptData0.begin(), scriptData0.end()), CScript(scriptData1.begin(), scriptData1.end()), CScript(scriptData2.begin(), scriptData2.end()) };
        const std::vector<CAmount> genesisReward = {5000000 * COIN, 50000000 * COIN, 36000000 * COIN};
        genesis = CreateGenesisBlock(1592638195, 2, consensus.InitialBaseTarget(), 1, genesisOutputScript, genesisReward);
        consensus.hashGenesisBlock = genesis.GetHash();
        auto str = consensus.hashGenesisBlock.ToString();

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;

        nSlotLength = 2048 / 8;
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
