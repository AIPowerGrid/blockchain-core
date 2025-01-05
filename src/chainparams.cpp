// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <deploymentinfo.h>
#include <llmq/params.h>
#include <util/ranges.h>
#include <util/system.h>
#include <util/underlying.h>
#include <versionbits.h>

#include <arith_uint256.h>

#include <assert.h>
extern int algoHashHits[16];
extern double algoHashTotal[16];

static CBlock CreateDevNetGenesisBlock(const uint256 &prevBlockHash, const std::string& devNetName, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    assert(!devNetName.empty());

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    // put height (BIP34) and devnet name into coinbase
    txNew.vin[0].scriptSig = CScript() << 1 << std::vector<unsigned char>(devNetName.begin(), devNetName.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 4;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock = prevBlockHash;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Bloomberg 10/30/23 Biden Signs Sweeping Order Regulating Artificial Intelligence";
    const CScript genesisOutputScript = CScript() << ParseHex("04f529c0007624ffa8c565cf9fbbcf406701b2a279a3ef06232069429b3c8c9fe8cac1b4062b418cdd4e4e2ea72ddbdf935a8f30fc3ca04d1844f6963332df8581") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock FindDevNetGenesisBlock(const CBlock &prevBlock, const CAmount& reward)
{
    std::string devNetName = gArgs.GetDevNetName();
    assert(!devNetName.empty());

    CBlock block = CreateDevNetGenesisBlock(prevBlock.GetHash(), devNetName, prevBlock.nTime + 1, 0, prevBlock.nBits, reward);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetHash();
        if (UintToArith256(hash) <= bnTarget)
            return block;
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("FindDevNetGenesisBlock: could not find devnet genesis block for %s", devNetName);
    assert(false);
}

bool CChainParams::IsValidMNActivation(int nBit, int64_t timePast) const
{
    assert(nBit < VERSIONBITS_NUM_BITS);

    for (int index = 0; index < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++index) {
        if (consensus.vDeployments[index].bit == nBit) {
            auto& deployment = consensus.vDeployments[index];
            if (timePast > deployment.nTimeout || timePast < deployment.nStartTime) {
                LogPrintf("%s: activation by bit=%d deployment='%s' is out of time range start=%lld timeout=%lld\n", __func__, nBit, VersionBitsDeploymentInfo[Consensus::DeploymentPos(index)].name, deployment.nStartTime, deployment.nTimeout);
                continue;
            }
            if (!deployment.useEHF) {
                LogPrintf("%s: trying to set MnEHF for non-masternode activation fork bit=%d\n", __func__, nBit);
                return false;
            }
            LogPrintf("%s: set MnEHF for bit=%d is valid\n", __func__, nBit);
            return true;
        }
    }
    LogPrintf("%s: WARNING: unknown MnEHF fork bit=%d\n", __func__, nBit);
    return true;
}

void CChainParams::AddLLMQ(Consensus::LLMQType llmqType)
{
    assert(!GetLLMQ(llmqType).has_value());
    for (const auto& llmq_param : Consensus::available_llmqs) {
        if (llmq_param.type == llmqType) {
            consensus.llmqs.push_back(llmq_param);
            return;
        }
    }
    error("CChainParams::%s: unknown LLMQ type %d", __func__, static_cast<uint8_t>(llmqType));
    assert(false);
}

std::optional<Consensus::LLMQParams> CChainParams::GetLLMQ(Consensus::LLMQType llmqType) const
{
    for (const auto& llmq_param : consensus.llmqs) {
        if (llmq_param.type == llmqType) {
            return std::make_optional(llmq_param);
        }
    }
    return std::nullopt;
}

static void FindMainNetGenesisBlock(uint32_t nTime, uint32_t nBits, const char* network)
{
    CBlock block = CreateGenesisBlock(nTime, 0, nBits, 4, 5000 * COIN);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);
    block.nNonce64 = -1;
    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;
        block.nNonce64++;
        uint256 mix_hash;
        uint256 hash = block.GetHashFull(mix_hash);
        if (nNonce % 48 == 0) {
            printf("\nrnonce=%d, pow is %s\n", nNonce, hash.GetHex().c_str());
        }
        if (UintToArith256(hash) <= bnTarget) {
            block.mix_hash = mix_hash;
            printf("\n%s net\n", network);
            printf("\ngenesis is %s\n", block.ToString().c_str());
            printf("\npow is %s\n", hash.GetHex().c_str());
            printf("\ngenesisNonce is %d\n", nNonce);
            std::cout << "Genesis Merkle " << block.hashMerkleRoot.GetHex() << std::endl;
            return;
        }
    }

    error("%sNetGenesisBlock: could not find %s genesis block", network, network);
    assert(false);
}


/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 210240; // Note: actual number of blocks per calendar year with DGW v3 is ~200700 (for example 449750 - 249050)
        consensus.BIP16Height = 0;
        consensus.nMasternodePaymentsStartBlock = 100000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // actual historical value
        consensus.nMasternodePaymentsIncreasePeriod = 576*30; // 17280 - actual historical value
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 20000; // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 21900; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = 20000; // The block at which 12.1 goes live (end of final 12.0 budget cycle)
        consensus.nSuperblockStartHash = uint256();
        consensus.nSuperblockCycle = 21900; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nSuperblockMaturityWindow = 1662; // ~(60*24*3)/2.6, ~3 days before actual Superblock is emitted
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1; // 00000000000076d8fcea02ec0963de4abfd01e771fec0863f960c2c64fe6f357
        consensus.BIP66Height = 1; // 00000000000b1fa2dfa312863570e13fae9ca7b5566cb27e55422620b469aefa
        consensus.BIP147Height = 1; // 00000000000000117befca4fab5622514772f608852e5edd8df9c55464b6fe37
        consensus.CSVHeight = 1; // 00000000000002e3d3a6224cfce80bae367fd3283d1e5a8ba50e5e60b2d2905d
        consensus.DIP0001Height = 2; // 000000000000000cbc9cb551e8ee1ac7aa223585cbdfb755d3683bafd93679e4
        consensus.DIP0003Height = 2;
        consensus.DIP0003EnforcementHeight = 1047200;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 2; // 00000000000000112e41e4b3afda8b233b8cc07c532d2eac5de097b68358c43e
        consensus.BRRHeight = 1; // 000000000000000c5a124f3eccfbe6e17876dca79cec9e63dfa70d269113c926
        consensus.DIP0020Height = 1; // 000000000000000f64ed3bd9af1078177ac026f6aa2677aa4d8beeae43be56cc
        consensus.DIP0024Height = 1; // 0000000000000001342be9c0b75ad40c276beaad91616423c4d9cb101b3db438
        consensus.DIP0024QuorumsHeight = 1; // 000000000000001aa25181e4c466e593992c98f9eb21c69ee757b8bb0af50244
        consensus.V19Height = 1; // 0000000000000015e32e73052d663626327004c81c5c22cb8b42c361015c0eae
        consensus.MinBIP9WarningHeight = 1 + 5; // V19 activation height + miner confirmation window
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20
        consensus.nPowTargetTimespan = 2016 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing =  1 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 1;
        consensus.nPowDGWHeight = 1;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V20].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nStartTime = 1700006400;      // November 15, 2023
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nTimeout = 1731628800;        // November 15, 2024
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdStart = 3226;       // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdMin = 2420;         // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nFalloffCoeff = 5;            // this corresponds to 10 periods

        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nStartTime = 1704067200;   // January 1, 2024
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nTimeout = 1767225600; // January 1, 2026
        // NOTE: nWindowSize for MN_RR __MUST__ be greater than or equal to nSuperblockMaturityWindow for CSuperblock::GetPaymentsLimit() to work correctly
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdStart = 3226;     // 80% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdMin = 2420;       // 60% of 4032
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nFalloffCoeff = 5;          // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].useEHF = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); // 2029000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000fe8c99a7aacc5aff074278a8378e625c0d02e4894db8f09bab185f4eb6"); // 0

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x41; // A
        pchMessageStart[1] = 0x49; // I
        pchMessageStart[2] = 0x34; // 4
        pchMessageStart[3] = 0x45; // E
        nDefaultPort = 8865;
        nDefaultPlatformP2PPort = 26656;
        nDefaultPlatformHTTPPort = 443;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 45;
        m_assumed_chain_state_size = 1;

        //FindMainNetGenesisBlock(1725035286, 0x20001fff, "main");
        // uint32_t nGenesisTime = 1688352006;	
        
        // This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block

    //    arith_uint256 test;
    //    bool fNegative;
    //    bool fOverflow;
    //    test.SetCompact(0x1e00ffff, &fNegative, &fOverflow);
    //    std::cout << "Test threshold: " << test.GetHex() << "\n\n";

    //    int genesisNonce = 0;
    //    uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
    //    uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    //    for (int i=0;i<40000000;i++) {
    //        genesis = CreateGenesisBlock(1688352006, i, 0x1e00ffff, 4, 5000 * COIN);
    //        //genesis.hashPrevBlock = TempHashHolding;
    //        consensus.hashGenesisBlock = genesis.GetX16RHash();

    //        arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
    //        if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
    //            BestBlockHash = consensus.hashGenesisBlock;
    //            std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
    //            std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
    //        }

    //        TempHashHolding = consensus.hashGenesisBlock;

    //        if (BestBlockHashArith < test) {
    //            genesisNonce = i - 1;
    //            break;
    //        }
    //        //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
    //    }
    //    std::cout << "\n";
    //    std::cout << "\n";
    //    std::cout << "\n";

    //    std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
    //    std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
    //    std::cout << "Genesis Merkle " << genesis.hashMerkleRoot.GetHex() << std::endl;

    //    std::cout << "\n";
    //    std::cout << "\n";
    //    int totalHits = 0;
    //    double totalTime = 0.0;

    //    for(int x = 0; x < 16; x++) {
    //        totalHits += algoHashHits[x];
    //        totalTime += algoHashTotal[x];
    //        std::cout << "hash algo " << x << " hits " << algoHashHits[x] << " total " << algoHashTotal[x] << " avg " << algoHashTotal[x]/algoHashHits[x] << std::endl;
    //    }

    //    std::cout << "Totals: hash algo " <<  " hits " << totalHits << " total " << totalTime << " avg " << totalTime/totalHits << std::endl;

    //    genesis.hashPrevBlock = TempHashHolding;

    //    return;


	    uint32_t nGenesisTime = 1688352006; // October 30, 2023, at 00:00:00 UTC	

	    genesis = CreateGenesisBlock(nGenesisTime, 22801899, 0x1e00ffff, 4, 5000 * COIN);        
    
        consensus.hashGenesisBlock = genesis.GetX16RHash(); // Get the x16r hash	

        assert(consensus.hashGenesisBlock == uint256S("0x000000fe8c99a7aacc5aff074278a8378e625c0d02e4894db8f09bab185f4eb6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe04a78dcf0ad3d5c7f1ac4460c4c04bc333e677d52371b7453b5b09603b41d54"));


        // KAWPOW GENESISBLOCK WORKS!
        // FindMainNetGenesisBlock(1725978566, 0x20001fff, "Main");
        // uint32_t nGenesisTime = 1725978566;	
        
	    // genesis = CreateGenesisBlock(nGenesisTime, 326, 0x20001fff, 4, 5000 * COIN);
        // uint256 mix_hash;
        // consensus.hashGenesisBlock = genesis.GetHashFull(mix_hash);
        // genesis.mix_hash = mix_hash;
	    // assert(consensus.hashGenesisBlock == uint256S("0015390b454aec02756a5157e4d91ba73287ad628778c188085d339b48395859"));
        // assert(genesis.hashMerkleRoot == uint256S("978a6bdc0038f2590723c4874583aaf8d3f9177711e4eea62e6ce90ec218090c"));





        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // vSeeds.emplace_back("dnsseed.dash.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23);  // 'A' prefix
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,23);  // 'A' prefix
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Dash BIP44 coin type is '5'
        nExtCoinType = 2686;

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_50_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_400_60;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_60_75;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_100_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_400_85;

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;
        nLLMQConnectionRetryTimeout = 60;
        m_is_mockable_chain = false;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        vSporkAddresses = {"AVGjbxRQ6GV9JtNuBMYK3Cewjvk2u8RJSu"};
        nMinSporkKeys = 1;

        nKAAAWWWPOWActivationTime = 1724578706;
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;


        checkpointData = {
            {
                {0, uint256S("0x000000fe8c99a7aacc5aff074278a8378e625c0d02e4894db8f09bab185f4eb6")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
         // TODO to be specified in a future patch.
        };

        // getchaintxstats 17280 0000000000000020d5e38b6aef5bc8e430029444d7977b46f710c7d281ef1281
        chainTxData = ChainTxData{
                1701429301, // * UNIX timestamp of last known number of transactions (Block 1969000)
                0,   // * total number of transactions between genesis and that timestamp
                            //   (the tx=... number in the ChainStateFlushed debug.log lines)
                0.0,      // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 210240;
        consensus.BIP16Height = 0;
        consensus.nMasternodePaymentsStartBlock = 4010; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 4030;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on testnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nSuperblockMaturityWindow = 8;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 76;
        consensus.BIP34Hash = uint256S("0x000008ebb1db2598e897d17275285767717c6acfeac4c73def49fbea1ddcbcb6");
        consensus.BIP65Height = 2431; // 0000039cf01242c7f921dcb4806a5994bc003b48c1973ae0c89b67809c2bb2ab
        consensus.BIP66Height = 2075; // 0000002acdd29a14583540cb72e1c5cc83783560e38fa7081495d474fe1671f7
        consensus.BIP147Height = 4300; // 0000000040c1480d413c9203664253ab18da284130c329bf88fcfc84312bcbe0
        consensus.CSVHeight = 8064; // 00000005eb94d027e34649373669191188858a22c70f4a6d29105e559124cec7
        consensus.DIP0001Height = 5500; // 00000001d60a01d8f1f39011cc6b26e3a1c97a24238cab856c2da71a4dd801a9
        consensus.DIP0003Height = 7000;
        consensus.DIP0003EnforcementHeight = 7300;
        consensus.DIP0003EnforcementHash = uint256S("00000055ebc0e974ba3a3fb785c5ad4365a39637d4df168169ee80d313612f8f");
        consensus.DIP0008Height = 78800; // 000000000e9329d964d80e7dab2e704b43b6bd2b91fea1e9315d38932e55fb55
        consensus.BRRHeight = 387500; // 0000001537dbfd09dea69f61c1f8b2afa27c8dc91c934e144797761c9f10367b
        consensus.DIP0020Height = 414100; // 000000cf961868662fbfbb5d1af6f1caa1809f6a4e390efe5f8cd3031adea668
        consensus.DIP0024Height = 769700; // 0000008d84e4efd890ae95c70a7a6126a70a80e5c19e4cb264a5b3469aeef172
        consensus.DIP0024QuorumsHeight = 770730; // 0000003c43b3ae7fffe61278ca5537a0e256ebf4d709d45f0ab040271074d51e
        consensus.V19Height = 850100; // 000004728b8ff2a16b9d4eebb0fd61eeffadc9c7fe4b0ec0b5a739869401ab5b
        consensus.MinBIP9WarningHeight = 850100 + 2016;  // v19 activation height + miner confirmation window
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 4002; // nPowKGWHeight >= nPowDGWHeight means "no KGW"
        consensus.nPowDGWHeight = 4002; // TODO: make sure to drop all spork6 related code on next testnet reset
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V20].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nStartTime = 1693526400;     // Friday, September 1, 2023 0:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdStart = 80;         // 80% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdMin = 60;           // 60% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nFalloffCoeff = 5;            // this corresponds to 10 periods

        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nStartTime = 1693526400;   // Friday, September 1, 2023 0:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdStart = 80;       // 80% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdMin = 60;         // 60% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nFalloffCoeff = 5;          // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].useEHF = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000031779704a0f54b4"); // 1069875

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000034bfeb926662ba547c0b8dd4ba8cbb6e0c581f4e7d1bddce8f9ca3a608"); // 1069875

        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xe2;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0xff;
        nDefaultPort = 18865;
        nDefaultPlatformP2PPort = 22000;
        nDefaultPlatformHTTPPort = 22001;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 4;
        m_assumed_chain_state_size = 1;

	    uint32_t nGenesisTime = 1688352006; // October 30, 2023, at 00:00:00 UTC	

	    genesis = CreateGenesisBlock(nGenesisTime, 22801899, 0x1e00ffff, 4, 5000 * COIN);        
    
        consensus.hashGenesisBlock = genesis.GetX16RHash(); // Get the x16r hash	

        assert(consensus.hashGenesisBlock == uint256S("0x000000fe8c99a7aacc5aff074278a8378e625c0d02e4894db8f09bab185f4eb6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe04a78dcf0ad3d5c7f1ac4460c4c04bc333e677d52371b7453b5b09603b41d54"));

        vFixedSeeds.clear();
        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.dashdot.io"); // Just a static list of stable node(s), only supports x9

        // Testnet Dash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Testnet Dash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Dash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Testnet Dash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet Dash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_50_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        AddLLMQ(Consensus::LLMQType::LLMQ_25_67);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_50_60;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_60_75;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_25_67;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_50_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = true;
        nLLMQConnectionRetryTimeout = 60;
        m_is_mockable_chain = false;

        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55"};
        nMinSporkKeys = 1;

        checkpointData = {
            {
                {255, uint256S("0x0000080b600e06f4c07880673f027210f9314575f5f875fafe51971e268b886a")},
                {261, uint256S("0x00000c26026d0815a7e2ce4fa270775f61403c040647ff2c3091f99e894a4618")},
                {1999, uint256S("0x00000052e538d27fa53693efe6fb6892a0c1d26c0235f599171c48a3cce553b1")},
                {2999, uint256S("0x0000024bc3f4f4cb30d29827c13d921ad77d2c6072e586c7f60d83c2722cdcc5")},
                {96090, uint256S("0x00000000033df4b94d17ab43e999caaf6c4735095cc77703685da81254d09bba")},
                {200000, uint256S("0x000000001015eb5ef86a8fe2b3074d947bc972c5befe32b28dd5ce915dc0d029")},
                {395750, uint256S("0x000008b78b6aef3fd05ab78db8b76c02163e885305545144420cb08704dce538")},
                {470000, uint256S("0x0000009303aeadf8cf3812f5c869691dbd4cb118ad20e9bf553be434bafe6a52")},
                {794950, uint256S("0x000001860e4c7248a9c5cc3bc7106041750560dc5cd9b3a2641b49494bcff5f2")},
                {808000, uint256S("0x00000104cb60a2b5e00a8a4259582756e5bf0dca201c0993c63f0e54971ea91a")},
                {840000, uint256S("0x000000cd7c3084499912ae893125c13e8c3c656abb6e511dcec6619c3d65a510")},
                {851000, uint256S("0x0000014d3b875540ff75517b7fbb1714e25d50ce92f65d7086cfce357928bb02")},
                {905100, uint256S("0x0000020c5e0f86f385cbf8e90210de9a9fd63633f01433bf47a6b3227a2851fd")},
                {960000, uint256S("0x0000000386cf5061ea16404c66deb83eb67892fa4f79b9e58e5eaab097ec2bd6")},
                {1069875, uint256S("0x00000034bfeb926662ba547c0b8dd4ba8cbb6e0c581f4e7d1bddce8f9ca3a608")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            // TODO to be specified in a future patch.
        };

        // getchaintxstats 17280 00000034bfeb926662ba547c0b8dd4ba8cbb6e0c581f4e7d1bddce8f9ca3a608
        chainTxData = ChainTxData{
                1721770009, // * UNIX timestamp of last known number of transactions (Block 905100)
                6548039,    // * total number of transactions between genesis and that timestamp
                            //   (the tx=... number in the ChainStateFlushed debug.log lines)
                0.0152605485140752,       // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Devnet: The Development network intended for developers use.
 */
class CDevNetParams : public CChainParams {
public:
    explicit CDevNetParams(const ArgsManager& args) {
        strNetworkID = CBaseChainParams::DEVNET;
        consensus.nSubsidyHalvingInterval = 210240;
        consensus.BIP16Height = 0;
        consensus.nMasternodePaymentsStartBlock = 4010; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 4030;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on devnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on devnet
        consensus.nSuperblockMaturityWindow = 8;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1; // BIP34 activated immediately on devnet
        consensus.BIP65Height = 1; // BIP65 activated immediately on devnet
        consensus.BIP66Height = 1; // BIP66 activated immediately on devnet
        consensus.BIP147Height = 1; // BIP147 activated immediately on devnet
        consensus.CSVHeight = 1; // BIP68 activated immediately on devnet
        consensus.DIP0001Height = 2; // DIP0001 activated immediately on devnet
        consensus.DIP0003Height = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHeight = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 2; // DIP0008 activated immediately on devnet
        consensus.BRRHeight = 300;
        consensus.DIP0020Height = 300;
        consensus.DIP0024Height = 300;
        consensus.DIP0024QuorumsHeight = 300;
        consensus.V19Height = 300;
        consensus.MinBIP9WarningHeight = 300 + 2016; // v19 activation height + miner confirmation window
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 4001; // nPowKGWHeight >= nPowDGWHeight means "no KGW"
        consensus.nPowDGWHeight = 4001;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V20].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nStartTime = 1661990400; // Sep 1st, 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nWindowSize = 120;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdStart = 80; // 80% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdMin = 60;   // 60% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nFalloffCoeff = 5;     // this corresponds to 10 periods

        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nStartTime = 1661990400; // Sep 1st, 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nWindowSize = 120;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdStart = 80; // 80% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdMin = 60;   // 60% of 100
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nFalloffCoeff = 5;     // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].useEHF = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xe2;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0xff;
        pchMessageStart[3] = 0xce;
        nDefaultPort = 19799;
        nDefaultPlatformP2PPort = 22100;
        nDefaultPlatformHTTPPort = 22101;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateDevnetSubsidyAndDiffParametersFromArgs(args);
        genesis = CreateGenesisBlock(1417713337, 1096447, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"));
        assert(genesis.hashMerkleRoot == uint256S("0xe0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7"));

        devnetGenesis = FindDevNetGenesisBlock(genesis, 50 * COIN);
        consensus.hashDevnetGenesisBlock = devnetGenesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("dashevo.org",  "devnet-seed.dashevo.org"));

        // Testnet Dash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Testnet Dash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Dash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Testnet Dash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet Dash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_50_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_60_75);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_60);
        AddLLMQ(Consensus::LLMQType::LLMQ_400_85);
        AddLLMQ(Consensus::LLMQType::LLMQ_100_67);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET_DIP0024);
        AddLLMQ(Consensus::LLMQType::LLMQ_DEVNET_PLATFORM);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_DEVNET;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_DEVNET_DIP0024;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_DEVNET_PLATFORM;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_DEVNET;

        UpdateDevnetLLMQChainLocksFromArgs(args);
        UpdateDevnetLLMQInstantSendDIP0024FromArgs(args);
        UpdateDevnetLLMQPlatformFromArgs(args);
        UpdateDevnetLLMQMnhfFromArgs(args);
        UpdateLLMQDevnetParametersFromArgs(args);
        UpdateDevnetPowTargetSpacingFromArgs(args);

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;
        nLLMQConnectionRetryTimeout = 60;
        m_is_mockable_chain = false;

        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55"};
        nMinSporkKeys = 1;

        checkpointData = (CCheckpointData) {
            {
                { 0, uint256S("0x000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e")},
                { 1, devnetGenesis.GetHash() },
            }
        };

        chainTxData = ChainTxData{
            devnetGenesis.GetBlockTime(), // * UNIX timestamp of devnet genesis block
            2,                            // * we only have 2 coinbase transactions when a devnet is started up
            0.01                          // * estimated number of transactions per second
        };
    }

    /**
     * Allows modifying the subsidy and difficulty devnet parameters.
     */
    void UpdateDevnetSubsidyAndDiffParameters(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
    {
        consensus.nMinimumDifficultyBlocks = nMinimumDifficultyBlocks;
        consensus.nHighSubsidyBlocks = nHighSubsidyBlocks;
        consensus.nHighSubsidyFactor = nHighSubsidyFactor;
    }
    void UpdateDevnetSubsidyAndDiffParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the LLMQ type for ChainLocks.
     */
    void UpdateDevnetLLMQChainLocks(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeChainLocks = llmqType;
    }
    void UpdateDevnetLLMQChainLocksFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the LLMQ type for InstantSend (DIP0024).
     */
    void UpdateDevnetLLMQDIP0024InstantSend(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeDIP0024InstantSend = llmqType;
    }

    /**
     * Allows modifying the LLMQ type for Platform.
     */
    void UpdateDevnetLLMQPlatform(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypePlatform = llmqType;
    }

    /**
     * Allows modifying the LLMQ type for Mnhf.
     */
    void UpdateDevnetLLMQMnhf(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeMnhf = llmqType;
    }

    /**
     * Allows modifying PowTargetSpacing
     */
    void UpdateDevnetPowTargetSpacing(int64_t nPowTargetSpacing)
    {
        consensus.nPowTargetSpacing = nPowTargetSpacing;
    }

    /**
     * Allows modifying parameters of the devnet LLMQ
     */
    void UpdateLLMQDevnetParameters(int size, int threshold)
    {
        auto params = ranges::find_if(consensus.llmqs, [](const auto& llmq){ return llmq.type == Consensus::LLMQType::LLMQ_DEVNET;});
        assert(params != consensus.llmqs.end());
        params->size = size;
        params->minSize = threshold;
        params->threshold = threshold;
        params->dkgBadVotesThreshold = threshold;
    }
    void UpdateLLMQDevnetParametersFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQInstantSendFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQInstantSendDIP0024FromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQPlatformFromArgs(const ArgsManager& args);
    void UpdateDevnetLLMQMnhfFromArgs(const ArgsManager& args);
    void UpdateDevnetPowTargetSpacingFromArgs(const ArgsManager& args);
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockStartHash = uint256(); // do not check this on regtest
        consensus.nSuperblockCycle = 20;
        consensus.nSuperblockMaturityWindow = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.BIP147Height = 432; // BIP147 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.DIP0001Height = 2000;
        consensus.DIP0003Height = 432;
        consensus.DIP0003EnforcementHeight = 500;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.DIP0008Height = 432;
        consensus.BRRHeight = 1000; // see block_reward_reallocation_tests
        consensus.DIP0020Height = 300;
        consensus.DIP0024Height = 900;
        consensus.DIP0024QuorumsHeight = 900;
        consensus.V19Height = 900;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Dash: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Dash: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nPowKGWHeight = 15200; // same as mainnet
        consensus.nPowDGWHeight = 34140; // same as mainnet
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_V20].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nWindowSize = 400;
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdStart = 384; // 80% of 480
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nThresholdMin = 288;   // 60% of 480
        consensus.vDeployments[Consensus::DEPLOYMENT_V20].nFalloffCoeff = 5;     // this corresponds to 10 periods

        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nWindowSize = 12;
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdStart = 9; // 80% of 12
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nThresholdMin = 7;   // 60% of 7
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].nFalloffCoeff = 5;     // this corresponds to 10 periods
        consensus.vDeployments[Consensus::DEPLOYMENT_MN_RR].useEHF = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nDefaultPort = 19899;
        nDefaultPlatformP2PPort = 22200;
        nDefaultPlatformHTTPPort = 22201;
        nPruneAfterHeight = args.GetBoolArg("-fastprune", false) ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);
        UpdateDIP3ParametersFromArgs(args);
        UpdateDIP8ParametersFromArgs(args);
        UpdateBIP147ParametersFromArgs(args);
        UpdateBudgetParametersFromArgs(args);

	    uint32_t nGenesisTime = 1688352006; // October 30, 2023, at 00:00:00 UTC	

	    genesis = CreateGenesisBlock(nGenesisTime, 22801899, 0x1e00ffff, 4, 5000 * COIN);        
    
        consensus.hashGenesisBlock = genesis.GetX16RHash(); // Get the x16r hash	

        assert(consensus.hashGenesisBlock == uint256S("0x000000fe8c99a7aacc5aff074278a8378e625c0d02e4894db8f09bab185f4eb6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe04a78dcf0ad3d5c7f1ac4460c4c04bc333e677d52371b7453b5b09603b41d54"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        fRequireRoutableExternalIP = false;
        m_is_test_chain = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;
        nLLMQConnectionRetryTimeout = 1; // must be lower then the LLMQ signing session timeout so that tests have control over failing behavior
        m_is_mockable_chain = true;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nPoolMinParticipants = 2;
        nPoolMaxParticipants = 20;

        // privKey: cP4EKFyJsHT39LDqgdcB43Y3YXjNyjb5Fuas1GQSeAtjnZWmZEQK
        vSporkAddresses = {"yj949n1UH6fDhw6HtVE5VMj2iSTaSWBMcW"};
        nMinSporkKeys = 1;

        checkpointData = {
            {
                {0, uint256S("0x000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e")},
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            {
                110,
                {AssumeutxoHash{uint256S("0x9b2a277a3e3b979f1a539d57e949495d7f8247312dbc32bce6619128c192b44b")}, 110},
            },
            {
                210,
                {AssumeutxoHash{uint256S("0xd4c97d32882583b057efc3dce673e44204851435e6ffcef20346e69cddc7c91e")}, 210},
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Regtest Dash addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Regtest Dash script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Dash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Regtest Dash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Regtest Dash BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_V17);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_DIP0024);
        AddLLMQ(Consensus::LLMQType::LLMQ_TEST_PLATFORM);
        consensus.llmqTypeChainLocks = Consensus::LLMQType::LLMQ_TEST;
        consensus.llmqTypeDIP0024InstantSend = Consensus::LLMQType::LLMQ_TEST_DIP0024;
        consensus.llmqTypePlatform = Consensus::LLMQType::LLMQ_TEST_PLATFORM;
        consensus.llmqTypeMnhf = Consensus::LLMQType::LLMQ_TEST;

        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST);
        UpdateLLMQTestParametersFromArgs(args, Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);
        UpdateLLMQInstantSendDIP0024FromArgs(args);
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int min_activation_height, int64_t nWindowSize, int64_t nThresholdStart, int64_t nThresholdMin, int64_t nFalloffCoeff, int64_t nUseEHF)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].min_activation_height = min_activation_height;
        if (nWindowSize != -1) {
            consensus.vDeployments[d].nWindowSize = nWindowSize;
        }
        if (nThresholdStart != -1) {
            consensus.vDeployments[d].nThresholdStart = nThresholdStart;
        }
        if (nThresholdMin != -1) {
            consensus.vDeployments[d].nThresholdMin = nThresholdMin;
        }
        if (nFalloffCoeff != -1) {
            consensus.vDeployments[d].nFalloffCoeff = nFalloffCoeff;
        }
        if (nUseEHF != -1) {
            consensus.vDeployments[d].useEHF = nUseEHF > 0;
        }
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the DIP3 activation and enforcement height
     */
    void UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
    {
        consensus.DIP0003Height = nActivationHeight;
        consensus.DIP0003EnforcementHeight = nEnforcementHeight;
    }
    void UpdateDIP3ParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the DIP8 activation height
     */
    void UpdateDIP8Parameters(int nActivationHeight)
    {
        consensus.DIP0008Height = nActivationHeight;
    }
    void UpdateDIP8ParametersFromArgs(const ArgsManager& args);

    void UpdateBIP147Parameters(int nActivationHeight)
    {
        consensus.BIP147Height = nActivationHeight;
    }
    void UpdateBIP147ParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying the budget regtest parameters.
     */
    void UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
    {
        consensus.nMasternodePaymentsStartBlock = nMasternodePaymentsStartBlock;
        consensus.nBudgetPaymentsStartBlock = nBudgetPaymentsStartBlock;
        consensus.nSuperblockStartBlock = nSuperblockStartBlock;
    }
    void UpdateBudgetParametersFromArgs(const ArgsManager& args);

    /**
     * Allows modifying parameters of the test LLMQ
     */
    void UpdateLLMQTestParameters(int size, int threshold, const Consensus::LLMQType llmqType)
    {
        auto params = ranges::find_if(consensus.llmqs, [llmqType](const auto& llmq){ return llmq.type == llmqType;});
        assert(params != consensus.llmqs.end());
        params->size = size;
        params->minSize = threshold;
        params->threshold = threshold;
        params->dkgBadVotesThreshold = threshold;
    }

    /**
     * Allows modifying the LLMQ type for InstantSend (DIP0024).
     */
    void UpdateLLMQDIP0024InstantSend(Consensus::LLMQType llmqType)
    {
        consensus.llmqTypeDIP0024InstantSend = llmqType;
    }

    void UpdateLLMQTestParametersFromArgs(const ArgsManager& args, const Consensus::LLMQType llmqType);
    void UpdateLLMQInstantSendDIP0024FromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() != 3 && vDeploymentParams.size() != 4 && vDeploymentParams.size() != 6 && vDeploymentParams.size() != 9) {
            throw std::runtime_error("Version bits parameters malformed, expecting "
                    "<deployment>:<start>:<end> or "
                    "<deployment>:<start>:<end>:<min_activation_height> or "
                    "<deployment>:<start>:<end>:<min_activation_height>:<window>:<threshold> or "
                    "<deployment>:<start>:<end>:<min_activation_height>:<window>:<thresholdstart>:<thresholdmin>:<falloffcoeff>:<useehf>");
        }
        int64_t nStartTime, nTimeout, nWindowSize = -1, nThresholdStart = -1, nThresholdMin = -1, nFalloffCoeff = -1, nUseEHF = -1;
        int min_activation_height = 0;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4 && !ParseInt32(vDeploymentParams[3], &min_activation_height)) {
            throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
        }
        if (vDeploymentParams.size() >= 6) {
            if (!ParseInt64(vDeploymentParams[4], &nWindowSize)) {
                throw std::runtime_error(strprintf("Invalid nWindowSize (%s)", vDeploymentParams[4]));
            }
            if (!ParseInt64(vDeploymentParams[5], &nThresholdStart)) {
                throw std::runtime_error(strprintf("Invalid nThresholdStart (%s)", vDeploymentParams[5]));
            }
        }
        if (vDeploymentParams.size() == 9) {
            if (!ParseInt64(vDeploymentParams[6], &nThresholdMin)) {
                throw std::runtime_error(strprintf("Invalid nThresholdMin (%s)", vDeploymentParams[6]));
            }
            if (!ParseInt64(vDeploymentParams[7], &nFalloffCoeff)) {
                throw std::runtime_error(strprintf("Invalid nFalloffCoeff (%s)", vDeploymentParams[7]));
            }
            if (!ParseInt64(vDeploymentParams[8], &nUseEHF)) {
                throw std::runtime_error(strprintf("Invalid nUseEHF (%s)", vDeploymentParams[8]));
            }
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, min_activation_height, nWindowSize, nThresholdStart, nThresholdMin, nFalloffCoeff, nUseEHF);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%ld, window=%ld, thresholdstart=%ld, thresholdmin=%ld, falloffcoeff=%ld, useehf=%ld\n",
                          vDeploymentParams[0], nStartTime, nTimeout, min_activation_height, nWindowSize, nThresholdStart, nThresholdMin, nFalloffCoeff, nUseEHF);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

void CRegTestParams::UpdateDIP3ParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-dip3params")) return;

    std::string strParams = args.GetArg("-dip3params", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 2) {
        throw std::runtime_error("DIP3 parameters malformed, expecting <activation>:<enforcement>");
    }
    int nDIP3ActivationHeight, nDIP3EnforcementHeight;
    if (!ParseInt32(vParams[0], &nDIP3ActivationHeight)) {
        throw std::runtime_error(strprintf("Invalid activation height (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &nDIP3EnforcementHeight)) {
        throw std::runtime_error(strprintf("Invalid enforcement height (%s)", vParams[1]));
    }
    LogPrintf("Setting DIP3 parameters to activation=%ld, enforcement=%ld\n", nDIP3ActivationHeight, nDIP3EnforcementHeight);
    UpdateDIP3Parameters(nDIP3ActivationHeight, nDIP3EnforcementHeight);
}

void CRegTestParams::UpdateDIP8ParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-dip8params")) return;

    std::string strParams = args.GetArg("-dip8params", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 1) {
        throw std::runtime_error("DIP8 parameters malformed, expecting <activation>");
    }
    int nDIP8ActivationHeight;
    if (!ParseInt32(vParams[0], &nDIP8ActivationHeight)) {
        throw std::runtime_error(strprintf("Invalid activation height (%s)", vParams[0]));
    }
    LogPrintf("Setting DIP8 parameters to activation=%ld\n", nDIP8ActivationHeight);
    UpdateDIP8Parameters(nDIP8ActivationHeight);
}

void CRegTestParams::UpdateBIP147ParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-bip147height")) return;
    int nBIP147Height;
    const std::string strParams = args.GetArg("-bip147height", "");
    if (!ParseInt32(strParams, &nBIP147Height)) {
        throw std::runtime_error(strprintf("Invalid activation height (%s)", strParams));
    }
    LogPrintf("Setting BIP147 parameters to activation=%lld\n", nBIP147Height);
    UpdateBIP147Parameters(nBIP147Height);
}

void CRegTestParams::UpdateBudgetParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-budgetparams")) return;

    std::string strParams = args.GetArg("-budgetparams", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 3) {
        throw std::runtime_error("Budget parameters malformed, expecting <masternode>:<budget>:<superblock>");
    }
    int nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock;
    if (!ParseInt32(vParams[0], &nMasternodePaymentsStartBlock)) {
        throw std::runtime_error(strprintf("Invalid masternode start height (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &nBudgetPaymentsStartBlock)) {
        throw std::runtime_error(strprintf("Invalid budget start block (%s)", vParams[1]));
    }
    if (!ParseInt32(vParams[2], &nSuperblockStartBlock)) {
        throw std::runtime_error(strprintf("Invalid superblock start height (%s)", vParams[2]));
    }
    LogPrintf("Setting budget parameters to masternode=%ld, budget=%ld, superblock=%ld\n", nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
    UpdateBudgetParameters(nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
}

void CRegTestParams::UpdateLLMQTestParametersFromArgs(const ArgsManager& args, const Consensus::LLMQType llmqType)
{
    assert(llmqType == Consensus::LLMQType::LLMQ_TEST || llmqType == Consensus::LLMQType::LLMQ_TEST_INSTANTSEND);

    std::string cmd_param{"-llmqtestparams"}, llmq_name{"LLMQ_TEST"};
    if (llmqType == Consensus::LLMQType::LLMQ_TEST_INSTANTSEND) {
        cmd_param = "-llmqtestinstantsendparams";
        llmq_name = "LLMQ_TEST_INSTANTSEND";
    }

    if (!args.IsArgSet(cmd_param)) return;

    std::string strParams = args.GetArg(cmd_param, "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 2) {
        throw std::runtime_error(strprintf("%s parameters malformed, expecting <size>:<threshold>", llmq_name));
    }
    int size, threshold;
    if (!ParseInt32(vParams[0], &size)) {
        throw std::runtime_error(strprintf("Invalid %s size (%s)", llmq_name, vParams[0]));
    }
    if (!ParseInt32(vParams[1], &threshold)) {
        throw std::runtime_error(strprintf("Invalid %s threshold (%s)", llmq_name, vParams[1]));
    }
    LogPrintf("Setting %s parameters to size=%ld, threshold=%ld\n", llmq_name, size, threshold);
    UpdateLLMQTestParameters(size, threshold, llmqType);
}

void CRegTestParams::UpdateLLMQInstantSendDIP0024FromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqtestinstantsenddip0024")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeDIP0024InstantSend);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqtestinstantsenddip0024", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqtestinstantsenddip0024.");
    }
    LogPrintf("Setting llmqtestinstantsenddip0024 to %ld\n", ToUnderlying(llmqType));
    UpdateLLMQDIP0024InstantSend(llmqType);
}

void CDevNetParams::UpdateDevnetSubsidyAndDiffParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-minimumdifficultyblocks") && !args.IsArgSet("-highsubsidyblocks") && !args.IsArgSet("-highsubsidyfactor")) return;

    int nMinimumDifficultyBlocks = gArgs.GetArg("-minimumdifficultyblocks", consensus.nMinimumDifficultyBlocks);
    int nHighSubsidyBlocks = gArgs.GetArg("-highsubsidyblocks", consensus.nHighSubsidyBlocks);
    int nHighSubsidyFactor = gArgs.GetArg("-highsubsidyfactor", consensus.nHighSubsidyFactor);
    LogPrintf("Setting minimumdifficultyblocks=%ld, highsubsidyblocks=%ld, highsubsidyfactor=%ld\n", nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
    UpdateDevnetSubsidyAndDiffParameters(nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
}

void CDevNetParams::UpdateDevnetLLMQChainLocksFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqchainlocks")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeChainLocks);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqchainlocks", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqchainlocks must NOT use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqchainlocks.");
    }
    LogPrintf("Setting llmqchainlocks to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQChainLocks(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQInstantSendDIP0024FromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqinstantsenddip0024")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeDIP0024InstantSend);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqinstantsenddip0024", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            if (!params.useRotation) {
                throw std::runtime_error("LLMQ type specified for -llmqinstantsenddip0024 must use rotation");
            }
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqinstantsenddip0024.");
    }
    LogPrintf("Setting llmqinstantsenddip0024 to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQDIP0024InstantSend(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQPlatformFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqplatform")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypePlatform);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqplatform", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqplatform.");
    }
    LogPrintf("Setting llmqplatform to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQPlatform(llmqType);
}

void CDevNetParams::UpdateDevnetLLMQMnhfFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqmnhf")) return;

    const auto& llmq_params_opt = GetLLMQ(consensus.llmqTypeMnhf);
    assert(llmq_params_opt.has_value());

    std::string strLLMQType = gArgs.GetArg("-llmqmnhf", std::string(llmq_params_opt->name));

    Consensus::LLMQType llmqType = Consensus::LLMQType::LLMQ_NONE;
    for (const auto& params : consensus.llmqs) {
        if (params.name == strLLMQType) {
            llmqType = params.type;
        }
    }
    if (llmqType == Consensus::LLMQType::LLMQ_NONE) {
        throw std::runtime_error("Invalid LLMQ type specified for -llmqmnhf.");
    }
    LogPrintf("Setting llmqmnhf to size=%ld\n", static_cast<uint8_t>(llmqType));
    UpdateDevnetLLMQMnhf(llmqType);
}

void CDevNetParams::UpdateDevnetPowTargetSpacingFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-powtargetspacing")) return;

    std::string strPowTargetSpacing = gArgs.GetArg("-powtargetspacing", "");

    int64_t powTargetSpacing;
    if (!ParseInt64(strPowTargetSpacing, &powTargetSpacing)) {
        throw std::runtime_error(strprintf("Invalid parsing of powTargetSpacing (%s)", strPowTargetSpacing));
    }

    if (powTargetSpacing < 1) {
        throw std::runtime_error(strprintf("Invalid value of powTargetSpacing (%s)", strPowTargetSpacing));
    }

    LogPrintf("Setting powTargetSpacing to %ld\n", powTargetSpacing);
    UpdateDevnetPowTargetSpacing(powTargetSpacing);
}

void CDevNetParams::UpdateLLMQDevnetParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-llmqdevnetparams")) return;

    std::string strParams = args.GetArg("-llmqdevnetparams", "");
    std::vector<std::string> vParams = SplitString(strParams, ':');
    if (vParams.size() != 2) {
        throw std::runtime_error("LLMQ_DEVNET parameters malformed, expecting <size>:<threshold>");
    }
    int size, threshold;
    if (!ParseInt32(vParams[0], &size)) {
        throw std::runtime_error(strprintf("Invalid LLMQ_DEVNET size (%s)", vParams[0]));
    }
    if (!ParseInt32(vParams[1], &threshold)) {
        throw std::runtime_error(strprintf("Invalid LLMQ_DEVNET threshold (%s)", vParams[1]));
    }
    LogPrintf("Setting LLMQ_DEVNET parameters to size=%ld, threshold=%ld\n", size, threshold);
    UpdateLLMQDevnetParameters(size, threshold);
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::DEVNET) {
        return std::unique_ptr<CChainParams>(new CDevNetParams(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
