// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2018-2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "zelnode/activezelnode.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "zelnode/zelnodeconfig.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "key_io.h"
#include "zelnode/benchmarks.h"
#include "util.h"

#include <univalue.h>

#include <boost/tokenizer.hpp>
#include <fstream>
#include <consensus/validation.h>

UniValue createzelnodekey(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createzelnodekey\n"
                "\nCreate a new zelnode private key\n"

                "\nResult:\n"
                "\"key\"    (string) Zelnode private key\n"

                "\nExamples:\n" +
                HelpExampleCli("createzelnodekey", "") + HelpExampleRpc("createzelnodekey", ""));

    CKey secret;
    secret.MakeNewKey(false);
    return EncodeSecret(secret);
}

UniValue createsporkkeys(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createsporkkeys\n"
                "\nCreate a set of private and public keys used for sporks\n"

                "\nResult:\n"
                "\"pubkey\"    (string) Spork public key\n"
                "\"privkey\"    (string) Spork private key\n"

                "\nExamples:\n" +
                HelpExampleCli("createsporkkeys", "") + HelpExampleRpc("createsporkkeys", ""));

    CKey secret;
    secret.MakeNewKey(false);

    CPubKey pubKey = secret.GetPubKey();

    std::string str;
    for (int i = 0; i < pubKey.size(); i++) {
        str += pubKey[i];
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("pubkey", HexStr(str)));
    ret.push_back(Pair("privkey", EncodeSecret(secret)));
    return ret;
}

UniValue getzelnodeoutputs(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "getzelnodeoutputs\n"
                "\nPrint all zelnode transaction outputs\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"txhash\": \"xxxx\",    (string) output transaction hash\n"
                "    \"outputidx\": n       (numeric) output index number\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodeoutputs", "") + HelpExampleRpc("getzelnodeoutputs", ""));

    // Find possible candidates
    vector<std::pair<COutput, CAmount>> possibleCoins = activeZelnode.SelectCoinsZelnode();

    UniValue ret(UniValue::VARR);
    for (auto& pair : possibleCoins) {
        COutput out = pair.first;
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txhash", out.tx->GetHash().ToString()));
        obj.push_back(Pair("outputidx", out.i));
        obj.push_back(Pair("ZEL Amount", pair.second / COIN));
        obj.push_back(Pair("Confirmations", pair.first.nDepth));
        ret.push_back(obj);
    }

    return ret;
}

UniValue createconfirmationtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createconfirmationtransaction\n"
                "\nCreate a new confirmation transaction and return the raw hex\n"

                "\nResult:\n"
                "    \"hex\": \"xxxx\",    (string) output transaction hex\n"

                "\nExamples:\n" +
                HelpExampleCli("createconfirmationtransaction", "") + HelpExampleRpc("createconfirmationtransaction", ""));

    if (!fZelnode) throw runtime_error("This is not a fluxnode");

    std::string errorMessage;
    CMutableTransaction mutTx;
    mutTx.nVersion = ZELNODE_TX_VERSION;

    activeZelnode.BuildDeterministicConfirmTx(mutTx, ZelnodeUpdateType::UPDATE_CONFIRM);

    if (!activeZelnode.SignDeterministicConfirmTx(mutTx, errorMessage)) {
        throw runtime_error(strprintf("Failed to sign new confirmation transaction: %s\n", errorMessage));
    }

    CTransaction tx(mutTx);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    return HexStr(ss.begin(), ss.end());
}

UniValue startzelnode(const UniValue& params, bool fHelp)
{

    std::string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();


    if (IsZelnodeTransactionsActive()) {
        if (fHelp || params.size() < 2 || params.size() > 3 ||
            (params.size() == 2 && (strCommand != "all")) ||
            (params.size() == 3 && strCommand != "alias"))
            throw runtime_error(
                    "startzelnode \"all|alias\" lockwallet ( \"alias\" )\n"
                    "\nAttempts to start one or more zelnode(s)\n"

                    "\nArguments:\n"
                    "1. set         (string, required) Specify which set of zelnode(s) to start.\n"
                    "2. lockwallet  (boolean, required) Lock wallet after completion.\n"
                    "3. alias       (string) Zelnode alias. Required if using 'alias' as the set.\n"

                    "\nResult: (for 'local' set):\n"
                    "\"status\"     (string) Zelnode status message\n"

                    "\nResult: (for other sets):\n"
                    "{\n"
                    "  \"overall\": \"xxxx\",     (string) Overall status message\n"
                    "  \"detail\": [\n"
                    "    {\n"
                    "      \"node\": \"xxxx\",    (string) Node name or alias\n"
                    "      \"result\": \"xxxx\",  (string) 'success' or 'failed'\n"
                    "      \"error\": \"xxxx\"    (string) Error message, if failed\n"
                    "    }\n"
                    "    ,...\n"
                    "  ]\n"
                    "}\n"

                    "\nExamples:\n" +
                    HelpExampleCli("startzelnode", "\"alias\" \"0\" \"my_zn\"") + HelpExampleRpc("startzelnode", "\"alias\" \"0\" \"my_zn\""));


        if (IsInitialBlockDownload(Params())) {
            throw runtime_error("Chain is still syncing, please wait until chain is synced\n");
        }

        bool fLock = (params[1].get_str() == "true" ? true : false);

        EnsureWalletIsUnlocked();

        bool fAlias = false;
        std::string alias = "";
        if (params.size() == 3) {
            fAlias = true;
            alias = params[2].get_str();
        }

        bool found = false;
        int successful = 0;
        int failed = 0;

        UniValue resultsObj(UniValue::VARR);

        for (ZelnodeConfig::ZelnodeEntry zne : zelnodeConfig.getEntries()) {
            UniValue zelnodeEntry(UniValue::VOBJ);

            if (fAlias && zne.getAlias() == alias) {
                found = true;
            } else if (fAlias) {
                continue;
            }

            std::string errorMessage;
            CMutableTransaction mutTransaction;

            int32_t index;
            zne.castOutputIndex(index);
            COutPoint outpoint = COutPoint(uint256S(zne.getTxHash()), index);

            zelnodeEntry.push_back(Pair("outpoint", outpoint.ToString()));
            zelnodeEntry.push_back(Pair("alias", zne.getAlias()));

            bool fChecked = false;
            if (mempool.mapZelnodeTxMempool.count(outpoint)) {
                zelnodeEntry.push_back(Pair("result", "failed"));
                zelnodeEntry.push_back(Pair("reason", "Mempool already has a zelnode transaction using this outpoint"));
            } else if (g_zelnodeCache.InStartTracker(outpoint)) {
                zelnodeEntry.push_back(Pair("result", "failed"));
                zelnodeEntry.push_back(Pair("reason", "Zelnode already started, waiting to be confirmed"));
            } else if (g_zelnodeCache.InDoSTracker(outpoint)) {
                zelnodeEntry.push_back(Pair("result", "failed"));
                zelnodeEntry.push_back(Pair("reason", "Zelnode already started then not confirmed, in DoS tracker. Must wait until out of DoS tracker to start"));
            } else if (g_zelnodeCache.InConfirmTracker(outpoint)) {
                zelnodeEntry.push_back(Pair("result", "failed"));
                zelnodeEntry.push_back(Pair("reason", "Zelnode already confirmed and in zelnode list"));
            } else {
                fChecked = true;
            }

            if (!fChecked) {
                resultsObj.push_back(zelnodeEntry);

                if (fAlias)
                    return resultsObj;
                else
                    continue;
            }

            mutTransaction.nVersion = ZELNODE_TX_VERSION;

            bool result = activeZelnode.BuildDeterministicStartTx(zne.getPrivKey(), zne.getTxHash(), zne.getOutputIndex(), errorMessage, mutTransaction);

            zelnodeEntry.push_back(Pair("transaction_built", result ? "successful" : "failed"));

            if (result) {
                CReserveKey reservekey(pwalletMain);
                std::string errorMessage;

                bool fSigned = false;
                if (activeZelnode.SignDeterministicStartTx(mutTransaction, errorMessage)) {
                    CTransaction tx(mutTransaction);
                    fSigned = true;

                    CWalletTx walletTx(pwalletMain, tx);
                    CValidationState state;
                    bool fCommited = pwalletMain->CommitTransaction(walletTx, reservekey, &state);
                    zelnodeEntry.push_back(Pair("transaction_commited", fCommited ? "successful" : "failed"));
                    if (fCommited) {
                        successful++;
                    } else {
                        errorMessage = state.GetRejectReason();
                        failed++;
                    }
                } else {
                    failed++;
                }
                zelnodeEntry.push_back(Pair("transaction_signed", fSigned ? "successful" : "failed"));
                zelnodeEntry.push_back(Pair("errorMessage", errorMessage));
            } else {
                failed++;
                zelnodeEntry.push_back(Pair("errorMessage", errorMessage));
            }

            resultsObj.push_back(zelnodeEntry);

            if (fAlias && found) {
                break;
            }
        }

        UniValue statusObj(UniValue::VOBJ);
        if (!found && fAlias) {
            failed++;
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("error", "could not find alias in config. Verify with list-conf."));
            resultsObj.push_back(statusObj);
        }

        if (fLock)
            pwalletMain->Lock();

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d zelnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
    return NullUniValue;
}

UniValue startdeterministiczelnode(const UniValue& params, bool fHelp)
{
    if (!IsZelnodeTransactionsActive()) {
        throw runtime_error("deterministic zelnodes transactions is not active yet");
    }

    std::string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp || params.size() != 2)
        throw runtime_error(
                "startdeterministiczelnode alias_name lockwallet\n"
                "\nAttempts to start one zelnode\n"

                "\nArguments:\n"
                "1. set         (string, required) Specify which set of zelnode(s) to start.\n"
                "2. lockwallet  (boolean, required) Lock wallet after completion.\n"
                "3. alias       (string) Zelnode alias. Required if using 'alias' as the set.\n"

                "\nResult: (for 'local' set):\n"
                "\"status\"     (string) Zelnode status message\n"

                "\nResult: (for other sets):\n"
                "{\n"
                "  \"overall\": \"xxxx\",     (string) Overall status message\n"
                "  \"detail\": [\n"
                "    {\n"
                "      \"node\": \"xxxx\",    (string) Node name or alias\n"
                "      \"result\": \"xxxx\",  (string) 'success' or 'failed'\n"
                "      \"error\": \"xxxx\"    (string) Error message, if failed\n"
                "    }\n"
                "    ,...\n"
                "  ]\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("startdeterministiczelnode", "\"alias_name\" false ") + HelpExampleRpc("startdeterministiczelnode", "\"alias_name\" false"));

    bool fLock = (params[1].get_str() == "true" ? true : false);

    EnsureWalletIsUnlocked();

    std::string alias = params[0].get_str();

    bool found = false;
    int successful = 0;
    int failed = 0;

    UniValue resultsObj(UniValue::VARR);
    UniValue statusObj(UniValue::VOBJ);
    statusObj.push_back(Pair("alias", alias));

    for (ZelnodeConfig::ZelnodeEntry zne : zelnodeConfig.getEntries()) {
        if (zne.getAlias() == alias) {
            found = true;
            std::string errorMessage;

            CMutableTransaction mutTransaction;

            int32_t index;
            zne.castOutputIndex(index);
            UniValue returnObj(UniValue::VOBJ);
            COutPoint outpoint = COutPoint(uint256S(zne.getTxHash()), index);
            if (mempool.mapZelnodeTxMempool.count(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Mempool already has a zelnode transaction using this outpoint"));
                return returnObj;
            } else if (g_zelnodeCache.InStartTracker(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Zelnode already started, waiting to be confirmed"));
                return returnObj;
            } else if (g_zelnodeCache.InDoSTracker(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Zelnode already started then not confirmed, in DoS tracker. Must wait until out of DoS tracker to start"));
                return returnObj;
            } else if (g_zelnodeCache.InConfirmTracker(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Zelnode already confirmed and in zelnode list"));
                return returnObj;
            }

            mutTransaction.nVersion = ZELNODE_TX_VERSION;

            bool result = activeZelnode.BuildDeterministicStartTx(zne.getPrivKey(), zne.getTxHash(), zne.getOutputIndex(), errorMessage, mutTransaction);

            statusObj.push_back(Pair("result", result ? "successful" : "failed"));

            if (result) {
                CReserveKey reservekey(pwalletMain);
                std::string errorMessage;

                if (activeZelnode.SignDeterministicStartTx(mutTransaction, errorMessage)) {
                    CTransaction tx(mutTransaction);

                    CWalletTx walletTx(pwalletMain, tx);
                    pwalletMain->CommitTransaction(walletTx, reservekey);
                    successful++;
                } else {
                    failed++;
                    statusObj.push_back(Pair("errorMessage", errorMessage));
                }
            } else {
                failed++;
                statusObj.push_back(Pair("errorMessage", errorMessage));
            }
            break;
        }
    }

    if (!found) {
        failed++;
        statusObj.push_back(Pair("result", "failed"));
        statusObj.push_back(Pair("error", "could not find alias in config. Verify with listzelnodeconf."));
    }

    resultsObj.push_back(statusObj);

    if (fLock)
        pwalletMain->Lock();

    UniValue returnObj(UniValue::VOBJ);
    returnObj.push_back(Pair("overall", strprintf("Successfully started %d zelnodes, failed to start %d, total %d", successful, failed, successful + failed)));
    returnObj.push_back(Pair("detail", resultsObj));

    return returnObj;
}

UniValue viewdeterministiczelnodelist(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "viewdeterministiczelnodelist ( \"filter\" )\n"
                "\nView the list in deterministric zelnode(s)\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"collateral\": n,                       (string) Collateral transaction\n"
                "    \"txhash\": \"hash\",                    (string) Collateral transaction hash\n"
                "    \"outidx\": n,                           (numeric) Collateral transaction output index\n"
                "    \"ip\": \"address\"                      (string) IP address\n"
                "    \"network\": \"network\"                 (string) Network type (IPv4, IPv6, onion)\n"
                "    \"added_height\": \"height\"             (string) Block height when zelnode was added\n"
                "    \"confirmed_height\": \"height\"         (string) Block height when zelnode was confirmed\n"
                "    \"last_confirmed_height\": \"height\"    (string) Last block height when zelnode was confirmed\n"
                "    \"last_paid_height\": \"height\"         (string) Last block height when zelnode was paid\n"
                "    \"tier\": \"type\",                      (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "    \"payment_address\": \"addr\",           (string) Zelnode ZEL address\n"
                "    \"pubkey\": \"key\",                     (string) Zelnode public key used for message broadcasting\n"
                "    \"activesince\": ttt,                    (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode has been active\n"
                "    \"lastpaid\": ttt,                       (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode was last paid\n"
                "    \"rank\": n                              (numberic) rank\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("viewdeterministiczelnodelist", ""));

    if (IsInitialBlockDownload(Params())) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Wait until chain is synced closer to tip");
    }

    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    UniValue wholelist(UniValue::VARR);
    int count = 0;
    for (const auto& item : g_zelnodeCache.mapZelnodeList.at(CUMULUS).listConfirmedZelnodes) {

        auto data = g_zelnodeCache.GetZelnodeData(item.out);

        UniValue info(UniValue::VOBJ);

        if (!data.IsNull()) {
            std::string strTxHash = data.collateralIn.GetTxHash();

            if (strFilter != "" && strTxHash.find(strFilter) == string::npos && HexStr(data.pubKey).find(strFilter) &&
                data.ip.find(strFilter) && EncodeDestination(data.collateralPubkey.GetID()).find(strFilter) == string::npos)
                continue;

            std::string strHost = data.ip;
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("txhash", strTxHash));
            info.push_back(std::make_pair("outidx", data.collateralIn.GetTxIndex()));
            info.push_back(std::make_pair("ip", data.ip));
            info.push_back(std::make_pair("network", strNetwork));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            info.push_back(std::make_pair("tier", TierToString(data.nTier)));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
            info.push_back(std::make_pair("pubkey", HexStr(data.pubKey)));
            if (chainActive.Height() >= data.nAddedBlockHeight)
                info.push_back(std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
            else
                info.push_back(std::make_pair("activesince", 0));
            if (chainActive.Height() >= data.nLastPaidHeight)
                info.push_back(std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
            else
                info.push_back(std::make_pair("lastpaid", 0));

            info.push_back(std::make_pair("rank", count++));

            wholelist.push_back(info);
        }


    }

    count = 0;
    for (const auto& item : g_zelnodeCache.mapZelnodeList.at(NIMBUS).listConfirmedZelnodes) {

        auto data = g_zelnodeCache.GetZelnodeData(item.out);

        UniValue info(UniValue::VOBJ);

        if (!data.IsNull())  {
            std::string strTxHash = data.collateralIn.GetTxHash();

            if (strFilter != "" && strTxHash.find(strFilter) == string::npos && HexStr(data.pubKey).find(strFilter) &&
                data.ip.find(strFilter) && EncodeDestination(data.collateralPubkey.GetID()).find(strFilter) == string::npos)
                continue;

            std::string strHost = data.ip;
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("txhash", data.collateralIn.GetTxHash()));
            info.push_back(std::make_pair("outidx", data.collateralIn.GetTxIndex()));
            info.push_back(std::make_pair("ip", data.ip));
            info.push_back(std::make_pair("network", strNetwork));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            info.push_back(std::make_pair("tier", TierToString(data.nTier)));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
            info.push_back(std::make_pair("pubkey", HexStr(data.pubKey)));
            if (chainActive.Height() >= data.nAddedBlockHeight)
                info.push_back(std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
            else
                info.push_back(std::make_pair("activesince", 0));
            if (chainActive.Height() >= data.nLastPaidHeight)
                info.push_back(std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
            else
                info.push_back(std::make_pair("lastpaid", 0));
            info.push_back(std::make_pair("rank", count++));

            wholelist.push_back(info);
        }


    }

    count = 0;
    for (const auto& item : g_zelnodeCache.mapZelnodeList.at(STRATUS).listConfirmedZelnodes) {

        auto data = g_zelnodeCache.GetZelnodeData(item.out);

        UniValue info(UniValue::VOBJ);

        if (!data.IsNull()) {
            std::string strTxHash = data.collateralIn.GetTxHash();

            if (strFilter != "" && strTxHash.find(strFilter) == string::npos && HexStr(data.pubKey).find(strFilter) &&
                data.ip.find(strFilter) && EncodeDestination(data.collateralPubkey.GetID()).find(strFilter) == string::npos)
                continue;

            std::string strHost = data.ip;
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("txhash", data.collateralIn.GetTxHash()));
            info.push_back(std::make_pair("outidx", data.collateralIn.GetTxIndex()));
            info.push_back(std::make_pair("ip", data.ip));
            info.push_back(std::make_pair("network", strNetwork));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            info.push_back(std::make_pair("tier", TierToString(data.nTier)));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
            info.push_back(std::make_pair("pubkey", HexStr(data.pubKey)));
            if (chainActive.Height() >= data.nAddedBlockHeight)
                info.push_back(std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
            else
                info.push_back(std::make_pair("activesince", 0));
            if (chainActive.Height() >= data.nLastPaidHeight)
                info.push_back(std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
            else
                info.push_back(std::make_pair("lastpaid", 0));
            info.push_back(std::make_pair("rank", count++));

            wholelist.push_back(info);
        }
    }

    return wholelist;
}

UniValue listzelnodes(const UniValue& params, bool fHelp)
{

    if (fHelp || (params.size() > 1))
        throw runtime_error(
                "listzelnodes ( \"filter\" )\n"
                "\nGet a ranked list of zelnodes\n"

                "\nArguments:\n"
                "1. \"filter\"    (string, optional) Filter search text. Partial match by txhash, status, or addr.\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"rank\": n,           (numeric) Zelnode Rank (or 0 if not enabled)\n"
                "    \"txhash\": \"hash\",  (string) Collateral transaction hash\n"
                "    \"outidx\": n,         (numeric) Collateral transaction output index\n"
                "    \"pubkey\": \"key\",   (string) Zelnode public key used for message broadcasting\n"
                "    \"status\": s,         (string) Status (ENABLED/EXPIRED/REMOVE/etc)\n"
                "    \"addr\": \"addr\",    (string) Zelnode ZEL address\n"
                "    \"version\": v,        (numeric) Zelnode protocol version\n"
                "    \"lastseen\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last seen\n"
                "    \"activetime\": ttt,   (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode has been active\n"
                "    \"lastpaid\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode was last paid\n"
                "    \"tier\": \"type\",    (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "    \"ip\": \"address\"    (string) IP address\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("listzelnodes", "") + HelpExampleRpc("listzelnodes", ""));

    if (IsDZelnodeActive()) {
        UniValue wholelist(UniValue::VARR);

        int count = 0;
        for (const auto &item : g_zelnodeCache.mapZelnodeList.at(CUMULUS).listConfirmedZelnodes) {

            auto data = g_zelnodeCache.GetZelnodeData(item.out);

            UniValue info(UniValue::VOBJ);

            if (data.IsNull()) {
                info.push_back(std::make_pair("collateral", item.out.ToFullString()));
                info.push_back(std::make_pair("status", "expired"));
                info.push_back(std::make_pair("last_paid_height", item.nLastPaidHeight));
                info.push_back(std::make_pair("confirmed_height", item.nConfirmedBlockHeight));
                info.push_back(std::make_pair("activesince", 0));
                info.push_back(std::make_pair("lastpaid", 0));
            } else {
                info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
                info.push_back(std::make_pair("ip", data.ip));
                info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
                info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
                info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
                info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
                info.push_back(std::make_pair("tier", TierToString(data.nTier)));
                info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
                if (chainActive.Height() >= data.nAddedBlockHeight)
                    info.push_back(
                            std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
                else
                    info.push_back(std::make_pair("activesince", 0));
                if (chainActive.Height() >= data.nLastPaidHeight)
                    info.push_back(
                            std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
                else
                    info.push_back(std::make_pair("lastpaid", 0));
                info.push_back(std::make_pair("rank", count++));
            }

            wholelist.push_back(info);
        }

        count = 0;
        for (const auto &item : g_zelnodeCache.mapZelnodeList.at(NIMBUS).listConfirmedZelnodes) {

            auto data = g_zelnodeCache.GetZelnodeData(item.out);

            UniValue info(UniValue::VOBJ);
            if (data.IsNull()) {
                info.push_back(std::make_pair("collateral", item.out.ToFullString()));
                info.push_back(std::make_pair("status", "expired"));
                info.push_back(std::make_pair("last_paid_height", item.nLastPaidHeight));
                info.push_back(std::make_pair("confirmed_height", item.nConfirmedBlockHeight));
                info.push_back(std::make_pair("activesince", 0));
                info.push_back(std::make_pair("lastpaid", 0));
            } else {
                info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
                info.push_back(std::make_pair("ip", data.ip));
                info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
                info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
                info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
                info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
                info.push_back(std::make_pair("tier", TierToString(data.nTier)));
                info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
                if (chainActive.Height() >= data.nAddedBlockHeight)
                    info.push_back(
                            std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
                else
                    info.push_back(std::make_pair("activesince", 0));
                if (chainActive.Height() >= data.nLastPaidHeight)
                    info.push_back(
                            std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
                else
                    info.push_back(std::make_pair("lastpaid", 0));
                info.push_back(std::make_pair("rank", count++));
            }

            wholelist.push_back(info);
        }

        count = 0;
        for (const auto &item : g_zelnodeCache.mapZelnodeList.at(STRATUS).listConfirmedZelnodes) {

            auto data = g_zelnodeCache.GetZelnodeData(item.out);

            UniValue info(UniValue::VOBJ);

            if (data.IsNull()) {
                info.push_back(std::make_pair("collateral", item.out.ToFullString()));
                info.push_back(std::make_pair("status", "expired"));
                info.push_back(std::make_pair("last_paid_height", item.nLastPaidHeight));
                info.push_back(std::make_pair("confirmed_height", item.nConfirmedBlockHeight));
                info.push_back(std::make_pair("activesince", 0));
                info.push_back(std::make_pair("lastpaid", 0));
            } else {
                info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
                info.push_back(std::make_pair("ip", data.ip));
                info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
                info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
                info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
                info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
                info.push_back(std::make_pair("tier", TierToString(data.nTier)));
                info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
                if (chainActive.Height() >= data.nAddedBlockHeight)
                    info.push_back(
                            std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
                else
                    info.push_back(std::make_pair("activesince", 0));
                if (chainActive.Height() >= data.nLastPaidHeight)
                    info.push_back(
                            std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
                else
                    info.push_back(std::make_pair("lastpaid", 0));
                info.push_back(std::make_pair("rank", count++));
            }
            wholelist.push_back(info);
        }
        return wholelist;
    }

    return NullUniValue;
}

UniValue getdoslist(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getdoslist\n"
                "\nGet a list of all zelnodes in the DOS list\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"collateral\": \"hash\",  (string) Collateral transaction hash\n"
                "    \"added_height\": n,   (numeric) Height the zelnode start transaction was added to the chain\n"
                "    \"payment_address\": \"xxx\",   (string) The payment address associated with the zelnode\n"
                "    \"eligible_in\": n,     (numeric) The amount of blocks before the zelnode is eligible to be started again\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getdoslist", "") + HelpExampleRpc("getdoslist", ""));

    if (IsDZelnodeActive()) {
        UniValue wholelist(UniValue::VARR);

        std::map<int, std::vector<UniValue>> mapOrderedDosList;

        for (const auto& item : g_zelnodeCache.mapStartTxDosTracker) {

            // Get the data from the item in the map of dox tracking
            const ZelnodeCacheData data = item.second;

            UniValue info(UniValue::VOBJ);

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));

            int nCurrentHeight = chainActive.Height();
            int nEligibleIn = ZELNODE_DOS_REMOVE_AMOUNT - (nCurrentHeight - data.nAddedBlockHeight);
            info.push_back(std::make_pair("eligible_in",  nEligibleIn));

            mapOrderedDosList[nEligibleIn].emplace_back(info);
        }

        if (mapOrderedDosList.size()) {
            for (int i = 0; i < ZELNODE_DOS_REMOVE_AMOUNT + 1; i++) {
                if (mapOrderedDosList.count(i)) {
                    for (const auto& item : mapOrderedDosList.at(i)) {
                        wholelist.push_back(item);
                    }
                }
            }
        }

        return wholelist;
    }

    return NullUniValue;
}

UniValue getstartlist(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getstartlist\n"
                "\nGet a list of all zelnodes in the start list\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"collateral\": \"hash\",  (string) Collateral transaction hash\n"
                "    \"added_height\": n,   (numeric) Height the zelnode start transaction was added to the chain\n"
                "    \"payment_address\": \"xxx\",   (string) The payment address associated with the zelnode\n"
                "    \"expires_in\": n,     (numeric) The amount of blocks before the start transaction expires, unless a confirmation transaction is added to a block\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getstartlist", "") + HelpExampleRpc("getstartlist", ""));

    if (IsDZelnodeActive()) {
        UniValue wholelist(UniValue::VARR);

        std::map<int, std::vector<UniValue>> mapOrderedStartList;

        for (const auto& item : g_zelnodeCache.mapStartTxTracker) {

            // Get the data from the item in the map of dox tracking
            const ZelnodeCacheData data = item.second;

            UniValue info(UniValue::VOBJ);

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));


            // TODO, when merged with the code that increasese the start tx expiration to 80 -> ZELNODE_START_TX_EXPIRATION_HEIGHT
            // TODO Grab the expiration height with the new function that was created that takes into account he block height :)
            int nCurrentHeight = chainActive.Height();
            int nExpiresIn = ZELNODE_START_TX_EXPIRATION_HEIGHT - (nCurrentHeight - data.nAddedBlockHeight);
            info.push_back(std::make_pair("expires_in",  nExpiresIn));

            mapOrderedStartList[nExpiresIn].emplace_back(info);
        }

        if (mapOrderedStartList.size()) {
            for (int i = 0; i < ZELNODE_START_TX_EXPIRATION_HEIGHT + 1; i++) {
                if (mapOrderedStartList.count(i)) {
                    for (const auto& item : mapOrderedStartList.at(i)) {
                        wholelist.push_back(item);
                    }
                }
            }
        }

        return wholelist;
    }

    return NullUniValue;
}

UniValue getzelnodestatus (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "getzelnodestatus\n"
                "\nPrint zelnode status\n"

                "\nResult:\n"
                "{\n"
                "  \"status\": \"xxxx\",                    (string) Zelnode status\n"
                "  \"collateral\": n,                       (string) Collateral transaction\n"
                "  \"txhash\": \"xxxx\",                    (string) Collateral transaction hash\n"
                "  \"outidx\": n,                           (numeric) Collateral transaction output index number\n"
                "  \"ip\": \"xxxx\",                        (string) Zelnode network address\n"
                "  \"network\": \"network\",                (string) Network type (IPv4, IPv6, onion)\n"
                "  \"added_height\": \"height\",            (string) Block height when zelnode was added\n"
                "  \"confirmed_height\": \"height\",        (string) Block height when zelnode was confirmed\n"
                "  \"last_confirmed_height\": \"height\",   (string) Last block height when zelnode was confirmed\n"
                "  \"last_paid_height\": \"height\",        (string) Last block height when zelnode was paid\n"
                "  \"tier\": \"type\",                      (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "  \"payment_address\": \"xxxx\",           (string) ZEL address for zelnode payments\n"
                "  \"pubkey\": \"key\",                     (string) Zelnode public key used for message broadcasting\n"
                "  \"activesince\": ttt,                    (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode has been active\n"
                "  \"lastpaid\": ttt,                       (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode was last paid\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodestatus", "") + HelpExampleRpc("getzelnodestatus", ""));

    if (!fZelnode) throw runtime_error("This is not a zelnode");

    if (IsDZelnodeActive()) {
        int nLocation = ZELNODE_TX_ERROR;
        auto data = g_zelnodeCache.GetZelnodeData(activeZelnode.deterministicOutPoint, &nLocation);

        UniValue info(UniValue::VOBJ);

        if (data.IsNull()) {
            info.push_back(std::make_pair("status", "expired"));
            info.push_back(std::make_pair("collateral", activeZelnode.deterministicOutPoint.ToFullString()));
        } else {
            std::string strTxHash = data.collateralIn.GetTxHash();
            std::string strHost = data.ip;
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            info.push_back(std::make_pair("status", ZelnodeLocationToString(nLocation)));
            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("txhash", strTxHash));
            info.push_back(std::make_pair("outidx", data.collateralIn.GetTxIndex()));
            info.push_back(std::make_pair("ip", data.ip));
            info.push_back(std::make_pair("network", strNetwork));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            info.push_back(std::make_pair("tier", TierToString(data.nTier)));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
            info.push_back(std::make_pair("pubkey", HexStr(data.pubKey)));
            if (chainActive.Height() >= data.nAddedBlockHeight)
                info.push_back(std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
            else
                info.push_back(std::make_pair("activesince", 0));
            if (chainActive.Height() >= data.nLastPaidHeight)
                info.push_back(std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
            else
                info.push_back(std::make_pair("lastpaid", 0));
        }

        return info;
    }

    return NullUniValue;

}

UniValue zelnodecurrentwinner (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "zelnodecurrentwinner\n"
                "\nGet current zelnode winner\n"

                "\nResult:\n"
                "{\n"
                "  \"protocol\": xxxx,        (numeric) Protocol version\n"
                "  \"txhash\": \"xxxx\",      (string) Collateral transaction hash\n"
                "  \"pubkey\": \"xxxx\",      (string) ZN Public key\n"
                "  \"lastseen\": xxx,       (numeric) Time since epoch of last seen\n"
                "  \"activeseconds\": xxx,  (numeric) Seconds ZN has been active\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("zelnodecurrentwinner", "") + HelpExampleRpc("zelnodecurrentwinner", ""));



    if (IsDZelnodeActive()) {
        CTxDestination dest_basic;
        COutPoint outpoint_basic;
        UniValue ret(UniValue::VOBJ);
        if (g_zelnodeCache.GetNextPayment(dest_basic, CUMULUS, outpoint_basic)) {
            UniValue obj(UniValue::VOBJ);
            auto data = g_zelnodeCache.GetZelnodeData(outpoint_basic);
            obj.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            obj.push_back(std::make_pair("ip", data.ip));
            obj.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            obj.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            obj.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            obj.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            obj.push_back(std::make_pair("tier", TierToString(data.nTier)));
            obj.push_back(std::make_pair("payment_address", EncodeDestination(dest_basic)));
            ret.push_back(std::make_pair("CUMULUS Winner", obj));
        }

        CTxDestination dest_super;
        COutPoint outpoint_super;
        if (g_zelnodeCache.GetNextPayment(dest_super, NIMBUS, outpoint_super)) {
            UniValue obj(UniValue::VOBJ);
            auto data = g_zelnodeCache.GetZelnodeData(outpoint_super);
            obj.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            obj.push_back(std::make_pair("ip", data.ip));
            obj.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            obj.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            obj.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            obj.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            obj.push_back(std::make_pair("tier", TierToString(data.nTier)));
            obj.push_back(std::make_pair("payment_address", EncodeDestination(dest_super)));
            ret.push_back(std::make_pair("NIMBUS Winner", obj));
        }

        CTxDestination dest_bamf;
        COutPoint outpoint_bamf;
        if (g_zelnodeCache.GetNextPayment(dest_bamf, STRATUS, outpoint_bamf)) {
            UniValue obj(UniValue::VOBJ);
            auto data = g_zelnodeCache.GetZelnodeData(outpoint_bamf);
            obj.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            obj.push_back(std::make_pair("ip", data.ip));
            obj.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            obj.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            obj.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            obj.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            obj.push_back(std::make_pair("tier", TierToString(data.nTier)));
            obj.push_back(std::make_pair("payment_address", EncodeDestination(dest_bamf)));
            ret.push_back(std::make_pair("STRATUS Winner", obj));
        }

        return ret;
    }

    return NullUniValue;
}

UniValue getzelnodecount (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getzelnodecount\n"
                "\nGet zelnode count values\n"

                "\nResult:\n"
                "{\n"
                "  \"total\": n,        (numeric) Total zelnodes\n"
                "  \"stable\": n,       (numeric) Stable count\n"
                "  \"enabled\": n,      (numeric) Enabled zelnodes\n"
                "  \"inqueue\": n       (numeric) Zelnodes in queue\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodecount", "") + HelpExampleRpc("getzelnodecount", ""));

    UniValue obj(UniValue::VOBJ);

    if (IsDZelnodeActive())
    {
        int nCUMULUS = g_zelnodeCache.mapZelnodeList.at(CUMULUS).listConfirmedZelnodes.size();
        int nNIMBUS = g_zelnodeCache.mapZelnodeList.at(NIMBUS).listConfirmedZelnodes.size();
        int nSTRATUS = g_zelnodeCache.mapZelnodeList.at(STRATUS).listConfirmedZelnodes.size();

        int nTotal = g_zelnodeCache.mapConfirmedZelnodeData.size();

        obj.push_back(Pair("total", nTotal));
        obj.push_back(Pair("stable", nTotal));
        obj.push_back(Pair("basic-enabled", nCUMULUS));
        obj.push_back(Pair("super-enabled", nNIMBUS));
        obj.push_back(Pair("bamf-enabled", nSTRATUS));
        obj.push_back(Pair("cumulus-enabled", nCUMULUS));
        obj.push_back(Pair("nimbus-enabled", nNIMBUS));
        obj.push_back(Pair("stratus-enabled", nSTRATUS));

        int ipv4 = 0, ipv6 = 0, onion = 0;
        g_zelnodeCache.CountNetworks(ipv4, ipv6, onion);

        obj.push_back(Pair("ipv4", ipv4));
        obj.push_back(Pair("ipv6", ipv6));
        obj.push_back(Pair("onion", onion));

        return obj;
    }

    return NullUniValue;
}

UniValue listzelnodeconf (const UniValue& params, bool fHelp)
{
    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    if (fHelp || (params.size() > 1))
        throw runtime_error(
                "listzelnodeconf ( \"filter\" )\n"
                "\nPrint zelnode.conf in JSON format\n"

                "\nArguments:\n"
                "1. \"filter\"    (string, optional) Filter search text. Partial match on alias, address, txHash, or status.\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"alias\": \"xxxx\",                       (string) zelnode alias\n"
                "    \"status\": \"xxxx\",                      (string) zelnode status\n"
                "    \"collateral\": n,                         (string) Collateral transaction\n"
                "    \"txHash\": \"xxxx\",                      (string) transaction hash\n"
                "    \"outputIndex\": n,                        (numeric) transaction output index\n"
                "    \"privateKey\": \"xxxx\",                  (string) zelnode private key\n"
                "    \"address\": \"xxxx\",                     (string) zelnode IP address\n"
                "    \"ip\": \"xxxx\",                          (string) Zelnode network address\n"
                "    \"network\": \"network\",                  (string) Network type (IPv4, IPv6, onion)\n"
                "    \"added_height\": \"height\",              (string) Block height when zelnode was added\n"
                "    \"confirmed_height\": \"height\",          (string) Block height when zelnode was confirmed\n"
                "    \"last_confirmed_height\": \"height\",     (string) Last block height when zelnode was confirmed\n"
                "    \"last_paid_height\": \"height\",          (string) Last block height when zelnode was paid\n"
                "    \"tier\": \"type\",                        (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "    \"payment_address\": \"xxxx\",             (string) ZEL address for zelnode payments\n"
                "    \"activesince\": ttt,                      (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode has been active\n"
                "    \"lastpaid\": ttt,                         (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode was last paid\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("listzelnodeconf", "") + HelpExampleRpc("listzelnodeconf", ""));

    std::vector<ZelnodeConfig::ZelnodeEntry> zelnodeEntries;
    zelnodeEntries = zelnodeConfig.getEntries();

    UniValue ret(UniValue::VARR);

    for (ZelnodeConfig::ZelnodeEntry zelnode : zelnodeEntries) {
        if (IsDZelnodeActive()) {
            int nIndex;
            if (!zelnode.castOutputIndex(nIndex))
                continue;
            COutPoint out = COutPoint(uint256S(zelnode.getTxHash()), uint32_t(nIndex));

            int nLocation = ZELNODE_TX_ERROR;
            auto data = g_zelnodeCache.GetZelnodeData(out, &nLocation);

            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("alias", zelnode.getAlias()));
            info.push_back(Pair("status", ZelnodeLocationToString(nLocation)));
            info.push_back(Pair("collateral", out.ToFullString()));
            info.push_back(Pair("txHash", zelnode.getTxHash()));
            info.push_back(Pair("outputIndex", zelnode.getOutputIndex()));
            info.push_back(Pair("privateKey", zelnode.getPrivKey()));
            info.push_back(Pair("address", zelnode.getIp()));

            if (data.IsNull()) {
                info.push_back(std::make_pair("ip", "UNKNOWN"));
                info.push_back(std::make_pair("network", "UNKOWN"));
                info.push_back(std::make_pair("added_height", 0));
                info.push_back(std::make_pair("confirmed_height", 0));
                info.push_back(std::make_pair("last_confirmed_height", 0));
                info.push_back(std::make_pair("last_paid_height", 0));
                info.push_back(std::make_pair("tier", "UNKNOWN"));
                info.push_back(std::make_pair("payment_address", "UNKNOWN"));
                info.push_back(std::make_pair("activesince", 0));
                info.push_back(std::make_pair("lastpaid", 0));
            } else {
                std::string strHost = data.ip;
                CNetAddr node = CNetAddr(strHost, false);
                std::string strNetwork = GetNetworkName(node.GetNetwork());
                info.push_back(std::make_pair("ip", data.ip));
                info.push_back(std::make_pair("network", strNetwork));
                info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
                info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
                info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
                info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
                info.push_back(std::make_pair("tier", TierToString(data.nTier)));
                info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
                if (chainActive.Height() >= data.nAddedBlockHeight)
                    info.push_back(
                            std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
                else
                    info.push_back(std::make_pair("activesince", 0));
                if (chainActive.Height() >= data.nLastPaidHeight)
                    info.push_back(
                            std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
                else
                    info.push_back(std::make_pair("lastpaid", 0));
            }

            ret.push_back(info);
            continue;
        }
    }

    return ret;
}


UniValue getbenchmarks(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getbenchmarks\n"
                "\nCommand to test node benchmarks\n"

                "\nExamples:\n" +
                HelpExampleCli("getbenchmarks", "") + HelpExampleRpc("getbenchmarks", ""));

    return GetBenchmarks();
}

UniValue getbenchstatus(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getbenchstatus\n"
                "\nCommand to get status of zelbenchd\n"

                "\nExamples:\n" +
                HelpExampleCli("getbenchstatus", "") + HelpExampleRpc("getbenchstatus", ""));

    return GetZelBenchdStatus();
}


UniValue stopzelbenchd(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "stopzelbenchd\n"
                "\nStop zelbenchd\n"

                "\nExamples:\n" +
                HelpExampleCli("stopzelbenchd", "") + HelpExampleRpc("stopzelbenchd", ""));

    if (IsZelBenchdRunning()) {
        StopZelBenchd();
        return "Stopping process";
    }

    return "Not running";
}

UniValue startzelbenchd(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "startzelbenchd\n"
                "\nStart zelbenchd\n"

                "\nExamples:\n" +
                HelpExampleCli("startzelbenchd", "") + HelpExampleRpc("startzelbenchd", ""));

    if (!IsZelBenchdRunning()) {
        StartZelBenchd();
        return "Starting process";
    }

    return "Already running";
}




static const CRPCCommand commands[] =
        { //  category              name                      actor (function)         okSafeMode
                //  --------------------- ------------------------  -----------------------  ----------
                { "zelnode",    "createzelnodekey",       &createzelnodekey,       false  },
                { "zelnode",    "getzelnodeoutputs",      &getzelnodeoutputs,      false  },
                { "zelnode",    "startzelnode",           &startzelnode,           false  },
                { "zelnode",    "listzelnodes",           &listzelnodes,           false  },
                { "zelnode",    "getdoslist",             &getdoslist,             false  },
                { "zelnode",    "getstartlist",           &getstartlist,           false  },
                { "zelnode",    "getzelnodecount",        &getzelnodecount,        false  },
                { "zelnode",    "zelnodecurrentwinner",   &zelnodecurrentwinner,   false  }, /* uses wallet if enabled */
                { "zelnode",    "getzelnodestatus",       &getzelnodestatus,       false  },
                { "zelnode",    "listzelnodeconf",        &listzelnodeconf,        false  },
                {"zelnode",     "startdeterministiczelnode", &startdeterministiczelnode, false },
                {"zelnode",     "viewdeterministiczelnodelist", &viewdeterministiczelnodelist, false },

                { "benchmarks", "getbenchmarks",         &getbenchmarks,           false  },
                { "benchmarks", "getbenchstatus",        &getbenchstatus,          false  },
                { "benchmarks", "stopzelbenchd",        &stopzelbenchd,          false  },
                { "benchmarks", "startzelbenchd",       &startzelbenchd,         false  },

                /** Not shown in help menu */
                { "hidden",    "createsporkkeys",        &createsporkkeys,         false  },
                { "hidden",    "createconfirmationtransaction",        &createconfirmationtransaction,         false  }




        };


void RegisterZelnodeRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
