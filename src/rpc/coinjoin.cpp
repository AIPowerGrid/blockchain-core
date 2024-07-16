// Copyright (c) 2019-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/context.h>
#include <validation.h>
#include <coinjoin/context.h>
#include <coinjoin/server.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/strencodings.h>

#ifdef ENABLE_WALLET
#include <coinjoin/client.h>
#include <coinjoin/options.h>
#include <interfaces/coinjoin.h>
#include <wallet/rpcwallet.h>
#endif // ENABLE_WALLET

#include <univalue.h>

#ifdef ENABLE_WALLET
namespace {
void ValidateCoinJoinArguments()
{
    /* If CoinJoin is enabled, everything is working as expected, we can bail */
    if (CCoinJoinClientOptions::IsEnabled())
        return;

    /* CoinJoin is on by default, unless a command line argument says otherwise */
    if (!gArgs.GetBoolArg("-enablecoinjoin", true)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Mixing is disabled via -enablecoinjoin=0 command line option, remove it to enable mixing again");
    }

    /* Most likely something bad happened and we disabled it while running the wallet */
    throw JSONRPCError(RPC_INTERNAL_ERROR, "Mixing is disabled due to an internal error");
}
} // anonymous namespace

static RPCHelpMan coinjoin()
{
    return RPCHelpMan{"coinjoin",
        "\nAvailable commands:\n"
        "  start       - Start mixing\n"
        "  stop        - Stop mixing\n"
        "  reset       - Reset mixing",
        {
            {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "The command to execute"},
        },
        RPCResults{},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Must be a valid command");
},
    };
}

static RPCHelpMan coinjoin_reset()
{
    return RPCHelpMan{"coinjoin reset",
        "\nReset CoinJoin mixing\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "", "Status of request"
        },
        RPCExamples{
            HelpExampleCli("coinjoin reset", "")
          + HelpExampleRpc("coinjoin reset", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    const NodeContext& node = EnsureAnyNodeContext(request.context);

    if (node.mn_activeman) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Client-side mixing is not supported on masternodes");
    }

    ValidateCoinJoinArguments();

    CHECK_NONFATAL(node.coinjoin_loader);
    auto cj_clientman = node.coinjoin_loader->walletman().Get(wallet->GetName());

    CHECK_NONFATAL(cj_clientman);
    cj_clientman->ResetPool();

    return "Mixing was reset";
},
    };
}

static RPCHelpMan coinjoin_start()
{
    return RPCHelpMan{"coinjoin start",
        "\nStart CoinJoin mixing\n"
        "Wallet must be unlocked for mixing\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "", "Status of request"
        },
        RPCExamples{
            HelpExampleCli("coinjoin start", "")
          + HelpExampleRpc("coinjoin start", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    const NodeContext& node = EnsureAnyNodeContext(request.context);

    if (node.mn_activeman) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Client-side mixing is not supported on masternodes");
    }

    ValidateCoinJoinArguments();

    {
        LOCK(wallet->cs_wallet);
        if (wallet->IsLocked(true))
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please unlock wallet for mixing with walletpassphrase first.");
    }

    CHECK_NONFATAL(node.coinjoin_loader);
    auto cj_clientman = node.coinjoin_loader->walletman().Get(wallet->GetName());

    CHECK_NONFATAL(cj_clientman);
    if (!cj_clientman->StartMixing()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Mixing has been started already.");
    }

    const ChainstateManager& chainman = EnsureChainman(node);
    CTxMemPool& mempool = EnsureMemPool(node);
    CConnman& connman = EnsureConnman(node);
    bool result = cj_clientman->DoAutomaticDenominating(chainman.ActiveChainstate(), connman, mempool);
    return "Mixing " + (result ? "started successfully" : ("start failed: " + cj_clientman->GetStatuses().original + ", will retry"));
},
    };
}

static RPCHelpMan coinjoin_stop()
{
    return RPCHelpMan{"coinjoin stop",
        "\nStop CoinJoin mixing\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "", "Status of request"
        },
        RPCExamples{
            HelpExampleCli("coinjoin stop", "")
          + HelpExampleRpc("coinjoin stop", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;

    const NodeContext& node = EnsureAnyNodeContext(request.context);

    if (node.mn_activeman) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Client-side mixing is not supported on masternodes");
    }

    ValidateCoinJoinArguments();

    CHECK_NONFATAL(node.coinjoin_loader);
    auto cj_clientman = node.coinjoin_loader->walletman().Get(wallet->GetName());

    CHECK_NONFATAL(cj_clientman);
    if (!cj_clientman->IsMixing()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No mix session to stop");
    }
    cj_clientman->StopMixing();

    return "Mixing was stopped";
},
    };
}
#endif // ENABLE_WALLET

static RPCHelpMan getpoolinfo()
{
    return RPCHelpMan{"getpoolinfo",
                "DEPRECATED. Please use getcoinjoininfo instead.\n",
                {},
                RPCResults{},
                RPCExamples{""},
                [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "Please use getcoinjoininfo instead");
},
    };
}

static RPCHelpMan getcoinjoininfo()
{
            return RPCHelpMan{"getcoinjoininfo",
                "Returns an object containing an information about CoinJoin settings and state.\n",
                {},
                {
                    RPCResult{"for regular nodes",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "enabled", "Whether mixing functionality is enabled"},
                            {RPCResult::Type::BOOL, "multisession", "Whether CoinJoin Multisession option is enabled"},
                            {RPCResult::Type::NUM, "max_sessions", "How many parallel mixing sessions can there be at once"},
                            {RPCResult::Type::NUM, "max_rounds", "How many rounds to mix"},
                            {RPCResult::Type::NUM, "max_amount", "Target CoinJoin balance in " + CURRENCY_UNIT + ""},
                            {RPCResult::Type::NUM, "denoms_goal", "How many inputs of each denominated amount to target"},
                            {RPCResult::Type::NUM, "denoms_hardcap", "Maximum limit of how many inputs of each denominated amount to create"},
                            {RPCResult::Type::NUM, "queue_size", "How many queues there are currently on the network"},
                            {RPCResult::Type::BOOL, "running", "Whether mixing is currently running"},
                            {RPCResult::Type::ARR, "sessions", "",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::STR_HEX, "protxhash", "The ProTxHash of the masternode"},
                                    {RPCResult::Type::STR_HEX, "outpoint", "The outpoint of the masternode"},
                                    {RPCResult::Type::STR, "service", "The IP address and port of the masternode"},
                                    {RPCResult::Type::NUM, "denomination", "The denomination of the mixing session in " + CURRENCY_UNIT + ""},
                                    {RPCResult::Type::STR_HEX, "state", "Current state of the mixing session"},
                                    {RPCResult::Type::NUM, "entries_count", "The number of entries in the mixing session"},
                                }},
                            }},
                            {RPCResult::Type::NUM, "keys_left", /* optional */ true, "How many new keys are left since last automatic backup (if applicable)"},
                            {RPCResult::Type::STR, "warnings", "Warnings if any"},
                        }},
                    RPCResult{"for masternodes",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "queue_size", "How many queues there are currently on the network"},
                            {RPCResult::Type::NUM, "denomination", "The denomination of the mixing session in " + CURRENCY_UNIT + ""},
                            {RPCResult::Type::STR_HEX, "state", "Current state of the mixing session"},
                            {RPCResult::Type::NUM, "entries_count", "The number of entries in the mixing session"},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getcoinjoininfo", "")
            + HelpExampleRpc("getcoinjoininfo", "")
                },
                [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue obj(UniValue::VOBJ);

    const NodeContext& node = EnsureAnyNodeContext(request.context);
    if (node.mn_activeman) {
        node.cj_ctx->server->GetJsonInfo(obj);
        return obj;
    }

#ifdef ENABLE_WALLET
    CCoinJoinClientOptions::GetJsonInfo(obj);

    obj.pushKV("queue_size", node.cj_ctx->queueman->GetQueueSize());

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        return obj;
    }

    auto manager = node.coinjoin_loader->walletman().Get(wallet->GetName());
    CHECK_NONFATAL(manager != nullptr);
    manager->GetJsonInfo(obj);

    std::string warning_msg{""};
    if (wallet->IsLegacy()) {
        obj.pushKV("keys_left", wallet->nKeysLeftSinceAutoBackup);
        if (wallet->nKeysLeftSinceAutoBackup < COINJOIN_KEYS_THRESHOLD_WARNING) {
            warning_msg = "WARNING: keypool is almost depleted!";
        }
    }
    obj.pushKV("warnings", warning_msg);
#endif // ENABLE_WALLET

    return obj;
},
    };
}

void RegisterCoinJoinRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
    { //  category              name                          actor (function)         argNames
      //  ------------------------------------------------------------------------------------------------------
        { "dash",               "getpoolinfo",                &getpoolinfo,            {} },
        { "dash",               "getcoinjoininfo",            &getcoinjoininfo,        {} },
#ifdef ENABLE_WALLET
        { "dash",               "coinjoin",                   &coinjoin,               {"command"} },
        { "dash",               "coinjoin", "reset",          &coinjoin_reset,         {} },
        { "dash",               "coinjoin", "start",          &coinjoin_start,         {} },
        { "dash",               "coinjoin", "stop",           &coinjoin_stop,          {} },
#endif // ENABLE_WALLET
};
// clang-format on
    for (const auto& command : commands) {
        t.appendCommand(command.name, command.subname, &command);
    }
}
