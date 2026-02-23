#include <xrpld/app/misc/DelegateUtils.h>
#include <xrpld/app/tx/detail/SetAccount.h>
#include <xrpld/core/Config.h>

#include <xrpl/basics/Log.h>
#include <xrpl/ledger/View.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/Quality.h>
#include <xrpl/protocol/st.h>

namespace ripple {

TxConsequences
SetAccount::makeTxConsequences(PreflightContext const& ctx)
{
    // The SetAccount may be a blocker, but only if it sets or clears
    // specific account flags.
    auto getTxConsequencesCategory = [](STTx const& tx) {
        if (std::uint32_t const uTxFlags = tx.getFlags();
            uTxFlags & (tfRequireAuth | tfOptionalAuth))
            return TxConsequences::blocker;

        if (auto const uSetFlag = tx[~sfSetFlag]; uSetFlag &&
            (*uSetFlag == asfRequireAuth || *uSetFlag == asfDisableMaster ||
             *uSetFlag == asfAccountTxnID))
            return TxConsequences::blocker;

        if (auto const uClearFlag = tx[~sfClearFlag]; uClearFlag &&
            (*uClearFlag == asfRequireAuth || *uClearFlag == asfDisableMaster ||
             *uClearFlag == asfAccountTxnID))
            return TxConsequences::blocker;

        return TxConsequences::normal;
    };

    return TxConsequences{ctx.tx, getTxConsequencesCategory(ctx.tx)};
}

std::uint32_t
SetAccount::getFlagsMask(PreflightContext const& ctx)
{
    return tfAccountSetMask;
}

// new for zkp
struct ZkpPayload
{
    ripple::uint256 cm;
    ripple::uint256 nf;
};

// Return payload if present + valid.
// If a zkp memo is present but malformed (wrong length / multiple), set *malformed=true and return nullopt.
// If no zkp memo is present, set *malformed=false and return nullopt.
std::optional<ZkpPayload>
extractZkpPayload(ripple::STTx const& tx, bool* malformed)
{
    using namespace ripple;

    if (malformed)
        *malformed = false;

    if (!tx.isFieldPresent(sfMemos))
        return std::nullopt;

    auto const& memos = tx.getFieldArray(sfMemos);

    std::optional<ZkpPayload> found;

    for (auto const& item : memos)
    {
        STObject const& memoObj = item.isFieldPresent(sfMemo)
            ? item.getFieldObject(sfMemo)
            : item;

        if (!memoObj.isFieldPresent(sfMemoType) ||
            !memoObj.isFieldPresent(sfMemoFormat) ||
            !memoObj.isFieldPresent(sfMemoData))
            continue;

        auto const typeBlob = memoObj.getFieldVL(sfMemoType);
        auto const fmtBlob  = memoObj.getFieldVL(sfMemoFormat);
        auto const dataBlob = memoObj.getFieldVL(sfMemoData);

        std::string const memoType(typeBlob.begin(), typeBlob.end());
        std::string const memoFmt(fmtBlob.begin(), fmtBlob.end());

        if (memoType != "zkp" || memoFmt != "cmnf-v1")
            continue;

        // zkp memo present: validate
        if (dataBlob.size() != 64)
        {
            if (malformed) *malformed = true;
            return std::nullopt;
        }

        ZkpPayload p;
        std::memcpy(p.cm.begin(), dataBlob.data() + 0,  32);
        std::memcpy(p.nf.begin(), dataBlob.data() + 32, 32);

        if (found) // multiple zkp memos
        {
            if (malformed) *malformed = true;
            return std::nullopt;
        }

        found = p;
    }

    return found;
}



NotTEC
SetAccount::preflight(PreflightContext const& ctx)
{
    auto& tx = ctx.tx;
    auto& j = ctx.j;

    std::uint32_t const uTxFlags = tx.getFlags();

    std::uint32_t const uSetFlag = tx.getFieldU32(sfSetFlag);
    std::uint32_t const uClearFlag = tx.getFieldU32(sfClearFlag);

    if ((uSetFlag != 0) && (uSetFlag == uClearFlag))
    {
        JLOG(j.trace()) << "Malformed transaction: Set and clear same flag.";
        return temINVALID_FLAG;
    }

    //
    // RequireAuth
    //
    bool bSetRequireAuth =
        (uTxFlags & tfRequireAuth) || (uSetFlag == asfRequireAuth);
    bool bClearRequireAuth =
        (uTxFlags & tfOptionalAuth) || (uClearFlag == asfRequireAuth);

    if (bSetRequireAuth && bClearRequireAuth)
    {
        JLOG(j.trace()) << "Malformed transaction: Contradictory flags set.";
        return temINVALID_FLAG;
    }

    //
    // RequireDestTag
    //
    bool bSetRequireDest =
        (uTxFlags & tfRequireDestTag) || (uSetFlag == asfRequireDest);
    bool bClearRequireDest =
        (uTxFlags & tfOptionalDestTag) || (uClearFlag == asfRequireDest);

    if (bSetRequireDest && bClearRequireDest)
    {
        JLOG(j.trace()) << "Malformed transaction: Contradictory flags set.";
        return temINVALID_FLAG;
    }

    //
    // DisallowXRP
    //
    bool bSetDisallowXRP =
        (uTxFlags & tfDisallowXRP) || (uSetFlag == asfDisallowXRP);
    bool bClearDisallowXRP =
        (uTxFlags & tfAllowXRP) || (uClearFlag == asfDisallowXRP);

    if (bSetDisallowXRP && bClearDisallowXRP)
    {
        JLOG(j.trace()) << "Malformed transaction: Contradictory flags set.";
        return temINVALID_FLAG;
    }

    // TransferRate
    if (tx.isFieldPresent(sfTransferRate))
    {
        std::uint32_t uRate = tx.getFieldU32(sfTransferRate);

        if (uRate && (uRate < QUALITY_ONE))
        {
            JLOG(j.trace())
                << "Malformed transaction: Transfer rate too small.";
            return temBAD_TRANSFER_RATE;
        }

        if (uRate > 2 * QUALITY_ONE)
        {
            JLOG(j.trace())
                << "Malformed transaction: Transfer rate too large.";
            return temBAD_TRANSFER_RATE;
        }
    }

    // TickSize
    if (tx.isFieldPresent(sfTickSize))
    {
        auto uTickSize = tx[sfTickSize];
        if (uTickSize &&
            ((uTickSize < Quality::minTickSize) ||
             (uTickSize > Quality::maxTickSize)))
        {
            JLOG(j.trace()) << "Malformed transaction: Bad tick size.";
            return temBAD_TICK_SIZE;
        }
    }

    if (auto const mk = tx[~sfMessageKey])
    {
        if (mk->size() && !publicKeyType({mk->data(), mk->size()}))
        {
            JLOG(j.trace()) << "Invalid message key specified.";
            return telBAD_PUBLIC_KEY;
        }
    }

    if (auto const domain = tx[~sfDomain];
        domain && domain->size() > maxDomainLength)
    {
        JLOG(j.trace()) << "domain too long";
        return telBAD_DOMAIN;
    }

    // Configure authorized minting account:
    if (uSetFlag == asfAuthorizedNFTokenMinter &&
        !tx.isFieldPresent(sfNFTokenMinter))
        return temMALFORMED;

    if (uClearFlag == asfAuthorizedNFTokenMinter &&
        tx.isFieldPresent(sfNFTokenMinter))
        return temMALFORMED;

    // new for ZK: field validation
    bool malformed = false;
    (void)extractZkpPayload(ctx.tx, &malformed);

    if (malformed)
    {
        JLOG(j.trace()) << "Malformed tx: invalid zkp memo.";
        return temMALFORMED;
    }

    return tesSUCCESS;
}

NotTEC
SetAccount::checkPermission(ReadView const& view, STTx const& tx)
{
    // SetAccount is prohibited to be granted on a transaction level,
    // but some granular permissions are allowed.
    auto const delegate = tx[~sfDelegate];
    if (!delegate)
        return tesSUCCESS;

    auto const delegateKey = keylet::delegate(tx[sfAccount], *delegate);
    auto const sle = view.read(delegateKey);

    if (!sle)
        return terNO_DELEGATE_PERMISSION;

    std::unordered_set<GranularPermissionType> granularPermissions;
    loadGranularPermission(sle, ttACCOUNT_SET, granularPermissions);

    auto const uSetFlag = tx.getFieldU32(sfSetFlag);
    auto const uClearFlag = tx.getFieldU32(sfClearFlag);
    auto const uTxFlags = tx.getFlags();
    // We don't support any flag based granular permission under
    // AccountSet transaction. If any delegated account is trying to
    // update the flag on behalf of another account, it is not
    // authorized.
    if (uSetFlag != 0 || uClearFlag != 0 || uTxFlags & tfUniversalMask)
        return terNO_DELEGATE_PERMISSION;

    if (tx.isFieldPresent(sfEmailHash) &&
        !granularPermissions.contains(AccountEmailHashSet))
        return terNO_DELEGATE_PERMISSION;

    if (tx.isFieldPresent(sfWalletLocator) ||
        tx.isFieldPresent(sfNFTokenMinter))
        return terNO_DELEGATE_PERMISSION;

    if (tx.isFieldPresent(sfMessageKey) &&
        !granularPermissions.contains(AccountMessageKeySet))
        return terNO_DELEGATE_PERMISSION;

    if (tx.isFieldPresent(sfDomain) &&
        !granularPermissions.contains(AccountDomainSet))
        return terNO_DELEGATE_PERMISSION;

    if (tx.isFieldPresent(sfTransferRate) &&
        !granularPermissions.contains(AccountTransferRateSet))
        return terNO_DELEGATE_PERMISSION;

    if (tx.isFieldPresent(sfTickSize) &&
        !granularPermissions.contains(AccountTickSizeSet))
        return terNO_DELEGATE_PERMISSION;

    return tesSUCCESS;
}

TER
SetAccount::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfAccount];

    std::uint32_t const uTxFlags = ctx.tx.getFlags();

    auto const sle = ctx.view.read(keylet::account(id));
    if (!sle)
        return terNO_ACCOUNT;

    // new for zk: make sure nullifier does not already exist
    bool malformed = false;
    if (auto const payload = extractZkpPayload(ctx.tx, &malformed))
    {
        if (ctx.view.read(keylet::zkNullifier(payload->nf)))
        {
            JLOG(ctx.j.trace()) << "ZKP spend rejected: nullifier already exists.";
            return tecDUPLICATE;
        }
    }
    else if (malformed)
    {
        //should be caught by preflight but just in case
        JLOG(ctx.j.trace()) << "Malformed tx: invalid zkp memo in preclaim.";
        return temMALFORMED;
    }

    std::uint32_t const uFlagsIn = sle->getFieldU32(sfFlags);

    std::uint32_t const uSetFlag = ctx.tx.getFieldU32(sfSetFlag);

    // legacy AccountSet flags
    bool bSetRequireAuth =
        (uTxFlags & tfRequireAuth) || (uSetFlag == asfRequireAuth);

    //
    // RequireAuth
    //
    if (bSetRequireAuth && !(uFlagsIn & lsfRequireAuth))
    {
        if (!dirIsEmpty(ctx.view, keylet::ownerDir(id)))
        {
            JLOG(ctx.j.trace()) << "Retry: Owner directory not empty.";
            return (ctx.flags & tapRETRY) ? TER{terOWNERS} : TER{tecOWNERS};
        }
    }

    //
    // Clawback
    //
    {
        if (uSetFlag == asfAllowTrustLineClawback)
        {
            if (uFlagsIn & lsfNoFreeze)
            {
                JLOG(ctx.j.trace()) << "Can't set Clawback if NoFreeze is set";
                return tecNO_PERMISSION;
            }

            if (!dirIsEmpty(ctx.view, keylet::ownerDir(id)))
            {
                JLOG(ctx.j.trace()) << "Owner directory not empty.";
                return tecOWNERS;
            }
        }
        else if (uSetFlag == asfNoFreeze)
        {
            // Cannot set NoFreeze if clawback is enabled
            if (uFlagsIn & lsfAllowTrustLineClawback)
            {
                JLOG(ctx.j.trace())
                    << "Can't set NoFreeze if clawback is enabled";
                return tecNO_PERMISSION;
            }
        }
    }

    return tesSUCCESS;
}

TER
SetAccount::doApply()
{
    auto const sle = view().peek(keylet::account(account_));
    if (!sle)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    std::uint32_t const uFlagsIn = sle->getFieldU32(sfFlags);
    std::uint32_t uFlagsOut = uFlagsIn;

    STTx const& tx{ctx_.tx};
    std::uint32_t const uSetFlag{tx.getFieldU32(sfSetFlag)};
    std::uint32_t const uClearFlag{tx.getFieldU32(sfClearFlag)};

    // legacy AccountSet flags
    std::uint32_t const uTxFlags{tx.getFlags()};
    bool const bSetRequireDest{
        (uTxFlags & tfRequireDestTag) || (uSetFlag == asfRequireDest)};
    bool const bClearRequireDest{
        (uTxFlags & tfOptionalDestTag) || (uClearFlag == asfRequireDest)};
    bool const bSetRequireAuth{
        (uTxFlags & tfRequireAuth) || (uSetFlag == asfRequireAuth)};
    bool const bClearRequireAuth{
        (uTxFlags & tfOptionalAuth) || (uClearFlag == asfRequireAuth)};
    bool const bSetDisallowXRP{
        (uTxFlags & tfDisallowXRP) || (uSetFlag == asfDisallowXRP)};
    bool const bClearDisallowXRP{
        (uTxFlags & tfAllowXRP) || (uClearFlag == asfDisallowXRP)};

    bool const sigWithMaster{[&tx, &acct = account_]() {
        auto const spk = tx.getSigningPubKey();

        if (publicKeyType(makeSlice(spk)))
        {
            PublicKey const signingPubKey(makeSlice(spk));

            if (calcAccountID(signingPubKey) == acct)
                return true;
        }
        return false;
    }()};

    //
    // RequireAuth
    //
    if (bSetRequireAuth && !(uFlagsIn & lsfRequireAuth))
    {
        JLOG(j_.trace()) << "Set RequireAuth.";
        uFlagsOut |= lsfRequireAuth;
    }

    if (bClearRequireAuth && (uFlagsIn & lsfRequireAuth))
    {
        JLOG(j_.trace()) << "Clear RequireAuth.";
        uFlagsOut &= ~lsfRequireAuth;
    }

    //
    // RequireDestTag
    //
    if (bSetRequireDest && !(uFlagsIn & lsfRequireDestTag))
    {
        JLOG(j_.trace()) << "Set lsfRequireDestTag.";
        uFlagsOut |= lsfRequireDestTag;
    }

    if (bClearRequireDest && (uFlagsIn & lsfRequireDestTag))
    {
        JLOG(j_.trace()) << "Clear lsfRequireDestTag.";
        uFlagsOut &= ~lsfRequireDestTag;
    }

    //
    // DisallowXRP
    //
    if (bSetDisallowXRP && !(uFlagsIn & lsfDisallowXRP))
    {
        JLOG(j_.trace()) << "Set lsfDisallowXRP.";
        uFlagsOut |= lsfDisallowXRP;
    }

    if (bClearDisallowXRP && (uFlagsIn & lsfDisallowXRP))
    {
        JLOG(j_.trace()) << "Clear lsfDisallowXRP.";
        uFlagsOut &= ~lsfDisallowXRP;
    }

    //
    // DisableMaster
    //
    if ((uSetFlag == asfDisableMaster) && !(uFlagsIn & lsfDisableMaster))
    {
        if (!sigWithMaster)
        {
            JLOG(j_.trace()) << "Must use master key to disable master key.";
            return tecNEED_MASTER_KEY;
        }

        if ((!sle->isFieldPresent(sfRegularKey)) &&
            (!view().peek(keylet::signers(account_))))
        {
            // Account has no regular key or multi-signer signer list.
            return tecNO_ALTERNATIVE_KEY;
        }

        JLOG(j_.trace()) << "Set lsfDisableMaster.";
        uFlagsOut |= lsfDisableMaster;
    }

    if ((uClearFlag == asfDisableMaster) && (uFlagsIn & lsfDisableMaster))
    {
        JLOG(j_.trace()) << "Clear lsfDisableMaster.";
        uFlagsOut &= ~lsfDisableMaster;
    }

    //
    // DefaultRipple
    //
    if (uSetFlag == asfDefaultRipple)
    {
        JLOG(j_.trace()) << "Set lsfDefaultRipple.";
        uFlagsOut |= lsfDefaultRipple;
    }
    else if (uClearFlag == asfDefaultRipple)
    {
        JLOG(j_.trace()) << "Clear lsfDefaultRipple.";
        uFlagsOut &= ~lsfDefaultRipple;
    }

    //
    // NoFreeze
    //
    if (uSetFlag == asfNoFreeze)
    {
        if (!sigWithMaster && !(uFlagsIn & lsfDisableMaster))
        {
            JLOG(j_.trace()) << "Must use master key to set NoFreeze.";
            return tecNEED_MASTER_KEY;
        }

        JLOG(j_.trace()) << "Set NoFreeze flag";
        uFlagsOut |= lsfNoFreeze;
    }

    // Anyone may set global freeze
    if (uSetFlag == asfGlobalFreeze)
    {
        JLOG(j_.trace()) << "Set GlobalFreeze flag";
        uFlagsOut |= lsfGlobalFreeze;
    }

    // If you have set NoFreeze, you may not clear GlobalFreeze
    // This prevents those who have set NoFreeze from using
    // GlobalFreeze strategically.
    if ((uSetFlag != asfGlobalFreeze) && (uClearFlag == asfGlobalFreeze) &&
        ((uFlagsOut & lsfNoFreeze) == 0))
    {
        JLOG(j_.trace()) << "Clear GlobalFreeze flag";
        uFlagsOut &= ~lsfGlobalFreeze;
    }

    //
    // Track transaction IDs signed by this account in its root
    //
    if ((uSetFlag == asfAccountTxnID) && !sle->isFieldPresent(sfAccountTxnID))
    {
        JLOG(j_.trace()) << "Set AccountTxnID.";
        sle->makeFieldPresent(sfAccountTxnID);
    }

    if ((uClearFlag == asfAccountTxnID) && sle->isFieldPresent(sfAccountTxnID))
    {
        JLOG(j_.trace()) << "Clear AccountTxnID.";
        sle->makeFieldAbsent(sfAccountTxnID);
    }

    //
    // DepositAuth
    //
    if (uSetFlag == asfDepositAuth)
    {
        JLOG(j_.trace()) << "Set lsfDepositAuth.";
        uFlagsOut |= lsfDepositAuth;
    }
    else if (uClearFlag == asfDepositAuth)
    {
        JLOG(j_.trace()) << "Clear lsfDepositAuth.";
        uFlagsOut &= ~lsfDepositAuth;
    }

    //
    // EmailHash
    //
    if (tx.isFieldPresent(sfEmailHash))
    {
        uint128 const uHash = tx.getFieldH128(sfEmailHash);

        if (!uHash)
        {
            JLOG(j_.trace()) << "unset email hash";
            sle->makeFieldAbsent(sfEmailHash);
        }
        else
        {
            JLOG(j_.trace()) << "set email hash";
            sle->setFieldH128(sfEmailHash, uHash);
        }
    }

    //
    // WalletLocator
    //
    if (tx.isFieldPresent(sfWalletLocator))
    {
        uint256 const uHash = tx.getFieldH256(sfWalletLocator);

        if (!uHash)
        {
            JLOG(j_.trace()) << "unset wallet locator";
            sle->makeFieldAbsent(sfWalletLocator);
        }
        else
        {
            JLOG(j_.trace()) << "set wallet locator";
            sle->setFieldH256(sfWalletLocator, uHash);
        }
    }

    //
    // MessageKey
    //
    if (tx.isFieldPresent(sfMessageKey))
    {
        Blob const messageKey = tx.getFieldVL(sfMessageKey);

        if (messageKey.empty())
        {
            JLOG(j_.debug()) << "set message key";
            sle->makeFieldAbsent(sfMessageKey);
        }
        else
        {
            JLOG(j_.debug()) << "set message key";
            sle->setFieldVL(sfMessageKey, messageKey);
        }
    }

    //
    // Domain
    //
    if (tx.isFieldPresent(sfDomain))
    {
        Blob const domain = tx.getFieldVL(sfDomain);

        if (domain.empty())
        {
            JLOG(j_.trace()) << "unset domain";
            sle->makeFieldAbsent(sfDomain);
        }
        else
        {
            JLOG(j_.trace()) << "set domain";
            sle->setFieldVL(sfDomain, domain);
        }
    }

    //
    // TransferRate
    //
    if (tx.isFieldPresent(sfTransferRate))
    {
        std::uint32_t uRate = tx.getFieldU32(sfTransferRate);

        if (uRate == 0 || uRate == QUALITY_ONE)
        {
            JLOG(j_.trace()) << "unset transfer rate";
            sle->makeFieldAbsent(sfTransferRate);
        }
        else
        {
            JLOG(j_.trace()) << "set transfer rate";
            sle->setFieldU32(sfTransferRate, uRate);
        }
    }

    //
    // TickSize
    //
    if (tx.isFieldPresent(sfTickSize))
    {
        auto uTickSize = tx[sfTickSize];
        if ((uTickSize == 0) || (uTickSize == Quality::maxTickSize))
        {
            JLOG(j_.trace()) << "unset tick size";
            sle->makeFieldAbsent(sfTickSize);
        }
        else
        {
            JLOG(j_.trace()) << "set tick size";
            sle->setFieldU8(sfTickSize, uTickSize);
        }
    }

    // Configure authorized minting account:
    if (uSetFlag == asfAuthorizedNFTokenMinter)
        sle->setAccountID(sfNFTokenMinter, ctx_.tx[sfNFTokenMinter]);

    if (uClearFlag == asfAuthorizedNFTokenMinter &&
        sle->isFieldPresent(sfNFTokenMinter))
        sle->makeFieldAbsent(sfNFTokenMinter);

    if (uSetFlag == asfDisallowIncomingNFTokenOffer)
        uFlagsOut |= lsfDisallowIncomingNFTokenOffer;
    else if (uClearFlag == asfDisallowIncomingNFTokenOffer)
        uFlagsOut &= ~lsfDisallowIncomingNFTokenOffer;

    if (uSetFlag == asfDisallowIncomingCheck)
        uFlagsOut |= lsfDisallowIncomingCheck;
    else if (uClearFlag == asfDisallowIncomingCheck)
        uFlagsOut &= ~lsfDisallowIncomingCheck;

    if (uSetFlag == asfDisallowIncomingPayChan)
        uFlagsOut |= lsfDisallowIncomingPayChan;
    else if (uClearFlag == asfDisallowIncomingPayChan)
        uFlagsOut &= ~lsfDisallowIncomingPayChan;

    if (uSetFlag == asfDisallowIncomingTrustline)
        uFlagsOut |= lsfDisallowIncomingTrustline;
    else if (uClearFlag == asfDisallowIncomingTrustline)
        uFlagsOut &= ~lsfDisallowIncomingTrustline;

    // Set or clear flags for disallowing escrow
    if (ctx_.view().rules().enabled(featureTokenEscrow))
    {
        if (uSetFlag == asfAllowTrustLineLocking)
            uFlagsOut |= lsfAllowTrustLineLocking;
        else if (uClearFlag == asfAllowTrustLineLocking)
            uFlagsOut &= ~lsfAllowTrustLineLocking;
    }

    // Set flag for clawback
    if (ctx_.view().rules().enabled(featureClawback) &&
        uSetFlag == asfAllowTrustLineClawback)
    {
        JLOG(j_.trace()) << "set allow clawback";
        uFlagsOut |= lsfAllowTrustLineClawback;
    }

    if (uFlagsIn != uFlagsOut)
        sle->setFieldU32(sfFlags, uFlagsOut);

    // new for zk: insert new ledger entries for cm and nf
    if (auto const payload = extractZkpPayload(tx, nullptr))
    {
        // safety re-check to ensure nullifier not spent already
        if (view().read(keylet::zkNullifier(payload->nf)))
            return tecDUPLICATE;

        //insert commitment entry
        {
            auto const k = keylet::zkCommitment(payload->cm);
            auto zsle = std::make_shared<SLE>(k);
            zsle->setFieldH256(sfZkCommitment, payload->cm);
            view().insert(zsle);
        }

        //insert nullifier entry (mark spent)
        {
            auto const k = keylet::zkNullifier(payload->nf);
            auto zsle = std::make_shared<SLE>(k);
            zsle->setFieldH256(sfZkNullifier, payload->nf);
            view().insert(zsle);
        }
    }


    ctx_.view().update(sle);

    return tesSUCCESS;
}

}  // namespace ripple
