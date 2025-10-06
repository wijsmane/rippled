//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2025 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#ifndef RIPPLE_APP_MISC_LENDINGHELPERS_H_INCLUDED
#define RIPPLE_APP_MISC_LENDINGHELPERS_H_INCLUDED

#include <xrpl/ledger/View.h>
#include <xrpl/protocol/st.h>

namespace ripple {

struct PreflightContext;

// Lending protocol has dependencies, so capture them here.
bool
checkLendingProtocolDependencies(PreflightContext const& ctx);

Number
loanPeriodicRate(TenthBips32 interestRate, std::uint32_t paymentInterval);

// This structure is used internally to compute the breakdown of a
// single loan payment
struct PaymentComponents
{
    Number rawInterest;
    Number rawPrincipal;
    Number roundedInterest;
    Number roundedPrincipal;
    // We may not need roundedPayment
    Number roundedPayment;
    bool final = false;
};

// This structure is explained in the XLS-66 spec, section 3.2.4.4 (Failure
// Conditions)
struct LoanPaymentParts
{
    /// principal_paid is the amount of principal that the payment covered.
    Number principalPaid;
    /// interest_paid is the amount of interest that the payment covered.
    Number interestPaid;
    /**
     * value_change is the amount by which the total value of the Loan changed.
     *  If value_change < 0, Loan value decreased.
     *  If value_change > 0, Loan value increased.
     * This is 0 for regular payments.
     */
    Number valueChange;
    /// fee_paid is the amount of fee that the payment covered.
    Number feeToPay;

    LoanPaymentParts&
    operator+=(LoanPaymentParts const& other)
    {
        principalPaid += other.principalPaid;
        interestPaid += other.interestPaid;
        valueChange += other.valueChange;
        feeToPay += other.feeToPay;
        return *this;
    }
};

/// Ensure the periodic payment is always rounded consistently
template <AssetType A>
Number
roundPeriodicPayment(
    A const& asset,
    Number const& periodicPayment,
    std::int32_t scale)
{
    return roundToAsset(asset, periodicPayment, scale, Number::upward);
}

namespace detail {
// These functions should rarely be used directly. More often, the ultimate
// result needs to be roundToAsset'd.

Number
loanPeriodicPayment(
    Number const& principalOutstanding,
    Number const& periodicRate,
    std::uint32_t paymentsRemaining);

Number
loanPeriodicPayment(
    Number const& principalOutstanding,
    TenthBips32 interestRate,
    std::uint32_t paymentInterval,
    std::uint32_t paymentsRemaining);

Number
loanLatePaymentInterest(
    Number const& principalOutstanding,
    TenthBips32 lateInterestRate,
    NetClock::time_point parentCloseTime,
    std::uint32_t nextPaymentDueDate);

Number
loanAccruedInterest(
    Number const& principalOutstanding,
    Number const& periodicRate,
    NetClock::time_point parentCloseTime,
    std::uint32_t startDate,
    std::uint32_t prevPaymentDate,
    std::uint32_t paymentInterval);

inline Number
minusFee(Number const& value, TenthBips32 managementFeeRate)
{
    return tenthBipsOfValue(value, tenthBipsPerUnity - managementFeeRate);
}

template <AssetType A>
PaymentComponents
computePaymentComponents(
    A const& asset,
    std::int32_t scale,
    Number const& totalValueOutstanding,
    Number const& principalOutstanding,
    Number const& referencePrincipal,
    Number const& periodicPayment,
    Number const& periodicRate,
    std::uint32_t paymentRemaining)
{
    /*
     * This function is derived from the XLS-66 spec, section 3.2.4.1.1 (Regular
     * Payment)
     */
    XRPL_ASSERT_PARTS(
        isRounded(asset, totalValueOutstanding, scale) &&
            isRounded(asset, principalOutstanding, scale),
        "ripple::detail::computePaymentComponents",
        "Outstanding values are rounded");
    auto const roundedPeriodicPayment =
        roundPeriodicPayment(asset, periodicPayment, scale);
    if (paymentRemaining == 1 || totalValueOutstanding <= periodicPayment)
    {
        // If there's only one payment left, we need to pay off each of the loan
        // parts.
        //
        // The totalValueOutstanding should never be less than the
        // periodicPayment until the last scheduled payment, but if it ever is,
        // make it the last payment.
        Number rawInterest = totalValueOutstanding - referencePrincipal;
        Number roundedInterest = totalValueOutstanding - principalOutstanding;

        // This is only expected to be true on the last payment
        XRPL_ASSERT_PARTS(
            rawInterest + referencePrincipal ==
                roundedInterest + principalOutstanding,
            "ripple::detail::computePaymentComponents",
            "last payment is complete");

        return {
            .rawInterest = rawInterest,
            .rawPrincipal = referencePrincipal,
            .roundedInterest = roundedInterest,
            .roundedPrincipal = principalOutstanding,
            .roundedPayment = roundedInterest + principalOutstanding,
            .final = true};
    }
    /*
     * From the spec, once the periodicPayment is computed:
     *
     * The principal and interest portions can be derived as follows:
     *  interest = principalOutstanding * periodicRate
     *  principal = periodicPayment - interest
     */
    Number const rawInterest = referencePrincipal * periodicRate;
    Number const rawPrincipal = periodicPayment - rawInterest;
    XRPL_ASSERT_PARTS(
        rawInterest >= 0,
        "ripple::detail::computePaymentComponents",
        "valid raw interest");
    XRPL_ASSERT_PARTS(
        rawPrincipal > 0 && rawPrincipal <= referencePrincipal,
        "ripple::detail::computePaymentComponents",
        "valid raw principal");

    // if (count($A20), MIN(Z19, Z19 - FLOOR(AA19 - Y20, 1)), "")
    // Z19 = outstanding principal
    // AA19 = reference principal
    // Y20 = raw principal

    Number const roundedPrincipal = [&]() {
        Number const p = std::max(
            Number{},
            std::min(
                principalOutstanding,
                principalOutstanding -
                    roundToAsset(
                        asset,
                        referencePrincipal - rawPrincipal,
                        scale,
                        Number::downward)));
        // if the estimated principal payment would leave the principal higher
        // than the "total "after payment" value of the loan, make the principal
        // payment also take the principal down to that same "after" value.
        // This should mean that all interest is paid, or that the loan has some
        // tricky parameters.
        if (principalOutstanding - p >
            totalValueOutstanding - roundedPeriodicPayment)
            return roundedPeriodicPayment;
        // Use the amount that will get principal outstanding as close to
        // reference principal as possible, but don't pay more than the rounded
        // periodic payment, or we'll end up with negative interest.
        return std::min(p, roundedPeriodicPayment);
    }();

    // if(count($A20), if(AB19 < $B$5, AB19 - Z19, CEILING($B$10-W20, 1)), "")
    // AB19 = total loan value
    // $B$5 = periodic payment (unrounded)
    // Z19 = outstanding principal
    // $B$10 = periodic payment (rounded up)
    // W20 = rounded principal

    Number const roundedInterest = roundedPeriodicPayment - roundedPrincipal;
    XRPL_ASSERT_PARTS(
        roundedInterest >= 0 && isRounded(asset, roundedInterest, scale),
        "ripple::detail::computePaymentComponents",
        "valid rounded interest");
    XRPL_ASSERT_PARTS(
        roundedPrincipal >= 0 && roundedPrincipal <= principalOutstanding &&
            isRounded(asset, roundedPrincipal, scale),
        "ripple::detail::computePaymentComponents",
        "valid rounded principal");

    return {
        .rawInterest = rawInterest,
        .rawPrincipal = rawPrincipal,
        .roundedInterest = roundedInterest,
        .roundedPrincipal = roundedPrincipal,
        .roundedPayment = roundedPeriodicPayment};
}

struct PaymentComponentsPlus : public PaymentComponents
{
    Number fee{0};
    Number valueChange{0};

    PaymentComponentsPlus(
        PaymentComponents const& p,
        Number f,
        Number v = Number{})
        : PaymentComponents(p), fee(f), valueChange(v)
    {
    }
};

template <class NumberProxy, class Int32Proxy, class Int32OptionalProxy>
LoanPaymentParts
doPayment(
    PaymentComponentsPlus const& payment,
    NumberProxy& totalValueOutstandingProxy,
    NumberProxy& principalOutstandingProxy,
    NumberProxy& referencePrincipalProxy,
    Int32Proxy& paymentRemainingProxy,
    Int32Proxy& prevPaymentDateProxy,
    Int32OptionalProxy& nextDueDateProxy,
    std::uint32_t paymentInterval)
{
    XRPL_ASSERT_PARTS(
        nextDueDateProxy,
        "ripple::detail::doPayment",
        "Next due date proxy set");
    if (payment.final)
    {
        paymentRemainingProxy = 0;
        XRPL_ASSERT_PARTS(
            referencePrincipalProxy == payment.rawPrincipal,
            "ripple::detail::doPayment",
            "Full reference principal payment");
        XRPL_ASSERT_PARTS(
            principalOutstandingProxy == payment.roundedPrincipal,
            "ripple::detail::doPayment",
            "Full principal payment");
        XRPL_ASSERT_PARTS(
            totalValueOutstandingProxy ==
                payment.roundedPrincipal + payment.roundedInterest,
            "ripple::detail::doPayment",
            "Full value payment");

        prevPaymentDateProxy = *nextDueDateProxy;
        // Remove the field. This is the only condition where nextDueDate is
        // allowed to be removed.
        nextDueDateProxy = std::nullopt;
    }
    else
    {
        paymentRemainingProxy -= 1;

        prevPaymentDateProxy = *nextDueDateProxy;
        // STObject::OptionalField does not define operator+=, and I don't want
        // to add one right now.
        nextDueDateProxy = *nextDueDateProxy + paymentInterval;
    }
    // A single payment always pays the same amount of principal. Only the
    // interest and fees are extra for a late payment
    referencePrincipalProxy -= payment.rawPrincipal;
    principalOutstandingProxy -= payment.roundedPrincipal;
    totalValueOutstandingProxy -=
        payment.roundedPrincipal + payment.roundedInterest;

    return LoanPaymentParts{
        .principalPaid = payment.roundedPrincipal,
        .interestPaid = payment.roundedInterest,
        .valueChange = payment.valueChange,
        .feeToPay = payment.fee};
}

/* Handle possible late payments.
 *
 * If this function processed a late payment, the return value will be
 * a LoanPaymentParts object. If the loan is not late, the return will be an
 * Unexpected(tesSUCCESS). Otherwise, it'll be an Unexpected with the error code
 * the caller is expected to return.
 *
 *
 * This function is an implementation of the XLS-66 spec, based on
 * * section 3.2.4.3 (Transaction Pseudo-code), specifically the bit
 *   labeled "the payment is late"
 * * section 3.2.4.1.2 (Late Payment)
 */
template <AssetType A>
Expected<PaymentComponentsPlus, TER>
handleLatePayment(
    A const& asset,
    ApplyView const& view,
    Number const& principalOutstanding,
    std::int32_t nextDueDate,
    PaymentComponentsPlus const& periodic,
    TenthBips32 lateInterestRate,
    std::int32_t loanScale,
    Number const& latePaymentFee,
    STAmount const& amount,
    beast::Journal j)
{
    if (!hasExpired(view, nextDueDate))
        return Unexpected(tesSUCCESS);

    // the payment is late
    // Late payment interest is only the part of the interest that comes from
    // being late, as computed by 3.2.4.1.2.
    auto const latePaymentInterest = loanLatePaymentInterest(
        asset,
        principalOutstanding,
        lateInterestRate,
        view.parentCloseTime(),
        nextDueDate,
        loanScale);
    XRPL_ASSERT(
        latePaymentInterest >= 0,
        "ripple::detail::handleLatePayment : valid late interest");
    PaymentComponentsPlus const late{
        PaymentComponents{
            .rawInterest = periodic.rawInterest + latePaymentInterest,
            .rawPrincipal = periodic.rawPrincipal,
            .roundedInterest = periodic.roundedInterest + latePaymentInterest,
            .roundedPrincipal = periodic.roundedPrincipal,
            .roundedPayment = periodic.roundedPayment},
        // A late payment pays both the normal fee, and the extra fee
        periodic.fee + latePaymentFee,
        // A late payment increases the value of the loan by the difference
        // between periodic and late payment interest
        latePaymentInterest};
    auto const totalDue =
        late.roundedPrincipal + late.roundedInterest + late.fee;
    XRPL_ASSERT_PARTS(
        isRounded(asset, totalDue, loanScale),
        "ripple::detail::handleLatePayment",
        "total due is rounded");

    if (amount < totalDue)
    {
        JLOG(j.warn()) << "Late loan payment amount is insufficient. Due: "
                       << totalDue << ", paid: " << amount;
        return Unexpected(tecINSUFFICIENT_PAYMENT);
    }

    return late;
}

/* Handle possible full payments.
 *
 * If this function processed a full payment, the return value will be
 * a PaymentComponentsPlus object. If the payment should not be considered as a
 * full payment, the return will be an Unexpected(tesSUCCESS). Otherwise, it'll
 * be an Unexpected with the error code the caller is expected to return.
 */
template <AssetType A>
Expected<PaymentComponentsPlus, TER>
handleFullPayment(
    A const& asset,
    ApplyView& view,
    Number const& principalOutstanding,
    Number const& referencePrincipal,
    std::uint32_t paymentRemaining,
    std::uint32_t prevPaymentDate,
    std::uint32_t const startDate,
    std::uint32_t const paymentInterval,
    TenthBips32 const closeInterestRate,
    std::int32_t loanScale,
    Number const& totalInterestOutstanding,
    Number const& periodicRate,
    Number const& closePaymentFee,
    STAmount const& amount,
    beast::Journal j)
{
    if (paymentRemaining <= 1)
        // If this is the last payment, it has to be a regular payment
        return Unexpected(tesSUCCESS);

    auto const totalInterest = calculateFullPaymentInterest(
        asset,
        referencePrincipal,
        periodicRate,
        view.parentCloseTime(),
        paymentInterval,
        prevPaymentDate,
        startDate,
        closeInterestRate,
        loanScale,
        closePaymentFee);

    auto const closeFullPayment =
        principalOutstanding + totalInterest + closePaymentFee;

    if (amount < closeFullPayment)
        // If the payment is less than the full payment amount, it's not
        // sufficient to be a full payment, but that's not an error.
        return Unexpected(tesSUCCESS);

    // Make a full payment

    PaymentComponentsPlus const result{
        PaymentComponents{
            .rawInterest =
                principalOutstanding + totalInterest - referencePrincipal,
            .rawPrincipal = referencePrincipal,
            .roundedInterest = totalInterest,
            .roundedPrincipal = principalOutstanding,
            .roundedPayment = closeFullPayment,
            .final = true},
        // A full payment only pays the single close payment fee
        closePaymentFee,
        // A full payment decreases the value of the loan by the
        // difference between the interest paid and the expected
        // outstanding interest return
        totalInterest - totalInterestOutstanding};

    return result;
}

}  // namespace detail

template <AssetType A>
Number
valueMinusFee(
    A const& asset,
    Number const& value,
    TenthBips32 managementFeeRate,
    std::int32_t scale)
{
    return roundToAsset(
        asset, detail::minusFee(value, managementFeeRate), scale);
}

struct LoanProperties
{
    Number periodicPayment;
    Number totalValueOutstanding;
    Number interestOwedToVault;
    std::int32_t loanScale;
    Number firstPaymentPrincipal;
};

template <AssetType A>
LoanProperties
computeLoanProperties(
    A const& asset,
    Number const& principalOutstanding,
    Number const& referencePrincipal,
    TenthBips32 interestRate,
    std::uint32_t paymentInterval,
    std::uint32_t paymentsRemaining,
    TenthBips32 managementFeeRate)
{
    auto const periodicRate = loanPeriodicRate(interestRate, paymentInterval);
    XRPL_ASSERT(
        interestRate == 0 || periodicRate > 0,
        "ripple::loanMakePayment : valid rate");

    auto const periodicPayment = detail::loanPeriodicPayment(
        principalOutstanding, periodicRate, paymentsRemaining);
    Number const totalValueOutstanding = [&]() {
        NumberRoundModeGuard mg(Number::to_nearest);
        // Use STAmount's internal rounding instead of roundToAsset, because
        // we're going to use this result to determine the scale for all the
        // other rounding.
        return STAmount{
            asset,
            /*
             * This formula is from the XLS-66 spec, section 3.2.4.2 (Total
             * Loan Value Calculation), specifically "totalValueOutstanding
             * = ..."
             */
            periodicPayment * paymentsRemaining};
    }();
    // Base the loan scale on the total value, since that's going to be the
    // biggest number involved
    auto const loanScale = totalValueOutstanding.exponent();

    auto const firstPaymentPrincipal = [&]() {
        // Compute the unrounded parts for the first payment. Ensure that the
        // principal payment will actually change the principal.
        auto const paymentComponents = detail::computePaymentComponents(
            asset,
            loanScale,
            totalValueOutstanding,
            principalOutstanding,
            referencePrincipal,
            periodicPayment,
            periodicRate,
            paymentsRemaining);

        // We only care about the unrounded principal part. It needs to be large
        // enough that it will affect the reference principal.
        auto const remaining =
            referencePrincipal - paymentComponents.rawPrincipal;
        if (remaining == referencePrincipal)
            // No change, so the first payment effectively pays no principal.
            // Whether that's a problem is left to the caller.
            return Number{0};
        return paymentComponents.rawPrincipal;
    }();

    auto const interestOwedToVault = valueMinusFee(
        asset,
        /*
         * This formula is from the XLS-66 spec, section 3.2.4.2 (Total Loan
         * Value Calculation), specifically "totalInterestOutstanding = ..."
         */
        totalValueOutstanding - principalOutstanding,
        managementFeeRate,
        loanScale);

    return LoanProperties{
        .periodicPayment = periodicPayment,
        .totalValueOutstanding = totalValueOutstanding,
        .interestOwedToVault = interestOwedToVault,
        .loanScale = loanScale,
        .firstPaymentPrincipal = firstPaymentPrincipal};
}

template <AssetType A>
Number
calculateFullPaymentInterest(
    A const& asset,
    Number const& referencePrincipal,
    Number const& periodicRate,
    NetClock::time_point parentCloseTime,
    std::uint32_t paymentInterval,
    std::uint32_t prevPaymentDate,
    std::uint32_t startDate,
    TenthBips32 closeInterestRate,
    std::int32_t loanScale,
    Number const& closePaymentFee)
{
    // If there is more than one payment remaining, see if enough was
    // paid for a full payment
    auto const accruedInterest = roundToAsset(
        asset,
        detail::loanAccruedInterest(
            referencePrincipal,
            periodicRate,
            parentCloseTime,
            startDate,
            prevPaymentDate,
            paymentInterval),
        loanScale);
    XRPL_ASSERT(
        accruedInterest >= 0,
        "ripple::detail::handleFullPayment : valid accrued interest");
    auto const prepaymentPenalty = roundToAsset(
        asset,
        tenthBipsOfValue(referencePrincipal, closeInterestRate),
        loanScale);
    XRPL_ASSERT(
        prepaymentPenalty >= 0,
        "ripple::detail::handleFullPayment : valid prepayment "
        "interest");
    return accruedInterest + prepaymentPenalty;
}

#if LOANCOMPLETE
template <AssetType A>
Number
loanPeriodicPayment(
    A const& asset,
    Number const& principalOutstanding,
    Number const& periodicRate,
    std::uint32_t paymentsRemaining,
    std::int32_t scale)
{
    return roundPeriodicPayment(
        asset,
        detail::loanPeriodicPayment(
            principalOutstanding, periodicRate, paymentsRemaining),
        scale);
}

template <AssetType A>
Number
loanPeriodicPayment(
    A const& asset,
    Number const& principalOutstanding,
    TenthBips32 interestRate,
    std::uint32_t paymentInterval,
    std::uint32_t paymentsRemaining,
    std::int32_t scale)
{
    return loanPeriodicPayment(
        asset,
        principalOutstanding,
        loanPeriodicRate(interestRate, paymentInterval),
        paymentsRemaining,
        scale);
}

template <AssetType A>
Number
loanTotalValueOutstanding(
    A asset,
    std::int32_t scale,
    Number const& periodicPayment,
    std::uint32_t paymentsRemaining)
{
    return roundToAsset(
        asset,
        /*
         * This formula is from the XLS-66 spec, section 3.2.4.2 (Total Loan
         * Value Calculation), specifically "totalValueOutstanding = ..."
         */
        periodicPayment * paymentsRemaining,
        scale,
        Number::upward);
}

template <AssetType A>
Number
loanTotalValueOutstanding(
    A asset,
    std::int32_t scale,
    Number const& principalOutstanding,
    TenthBips32 interestRate,
    std::uint32_t paymentInterval,
    std::uint32_t paymentsRemaining)
{
    /*
     * This function is derived from the XLS-66 spec, section 3.2.4.2 (Total
     * Loan Value Calculation)
     */
    return loanTotalValueOutstanding(
        asset,
        scale,
        loanPeriodicPayment(
            asset,
            principalOutstanding,
            interestRate,
            paymentInterval,
            paymentsRemaining,
            scale),
        paymentsRemaining);
}

inline Number
loanTotalInterestOutstanding(
    Number const& principalOutstanding,
    Number const& totalValueOutstanding)
{
    /*
     * This formula is from the XLS-66 spec, section 3.2.4.2 (Total Loan
     * Value Calculation), specifically "totalInterestOutstanding = ..."
     */
    return totalValueOutstanding - principalOutstanding;
}

template <AssetType A>
Number
loanTotalInterestOutstanding(
    A asset,
    std::int32_t scale,
    Number const& principalOutstanding,
    TenthBips32 interestRate,
    std::uint32_t paymentInterval,
    std::uint32_t paymentsRemaining)
{
    /*
     * This formula is derived from the XLS-66 spec, section 3.2.4.2 (Total Loan
     * Value Calculation)
     */
    return loanTotalInterestOutstanding(
        principalOutstanding,
        loanTotalValueOutstanding(
            asset,
            scale,
            principalOutstanding,
            interestRate,
            paymentInterval,
            paymentsRemaining));
}
#endif

template <AssetType A>
Number
loanInterestOutstandingMinusFee(
    A const& asset,
    Number const& totalInterestOutstanding,
    TenthBips32 managementFeeRate,
    std::int32_t scale)
{
    return valueMinusFee(
        asset, totalInterestOutstanding, managementFeeRate, scale);
}

#if LOANCOMPLETE
template <AssetType A>
Number
loanInterestOutstandingMinusFee(
    A const& asset,
    std::int32_t scale,
    Number const& principalOutstanding,
    TenthBips32 interestRate,
    std::uint32_t paymentInterval,
    std::uint32_t paymentsRemaining,
    TenthBips32 managementFeeRate)
{
    return loanInterestOutstandingMinusFee(
        asset,
        loanTotalInterestOutstanding(
            asset,
            scale,
            principalOutstanding,
            interestRate,
            paymentInterval,
            paymentsRemaining),
        managementFeeRate,
        scale);
}
#endif

template <AssetType A>
Number
loanLatePaymentInterest(
    A const& asset,
    Number const& principalOutstanding,
    TenthBips32 lateInterestRate,
    NetClock::time_point parentCloseTime,
    std::uint32_t nextPaymentDueDate,
    std::int32_t const& scale)
{
    return roundToAsset(
        asset,
        detail::loanLatePaymentInterest(
            principalOutstanding,
            lateInterestRate,
            parentCloseTime,
            nextPaymentDueDate),
        scale);
}

template <AssetType A>
bool
isRounded(A const& asset, Number const& value, std::int32_t scale)
{
    return roundToAsset(asset, value, scale, Number::downward) ==
        roundToAsset(asset, value, scale, Number::upward);
}

template <AssetType A>
Expected<LoanPaymentParts, TER>
loanMakePayment(
    A const& asset,
    ApplyView& view,
    SLE::ref loan,
    STAmount const& amount,
    beast::Journal j)
{
    /*
     * This function is an implementation of the XLS-66 spec,
     * section 3.2.4.3 (Transaction Pseudo-code)
     */
    auto principalOutstandingProxy = loan->at(sfPrincipalOutstanding);
    auto paymentRemainingProxy = loan->at(sfPaymentRemaining);

    if (paymentRemainingProxy == 0 || principalOutstandingProxy == 0)
    {
        // Loan complete
        JLOG(j.warn()) << "Loan is already paid off.";
        return Unexpected(tecKILLED);
    }

    // Next payment due date must be set unless the loan is complete
    auto nextDueDateProxy = loan->at(~sfNextPaymentDueDate);
    if (!nextDueDateProxy)
    {
        JLOG(j.warn()) << "Loan next payment due date is not set.";
        return Unexpected(tecINTERNAL);
    }

    std::int32_t const loanScale = loan->at(sfLoanScale);
    auto totalValueOutstandingProxy = loan->at(sfTotalValueOutstanding);
    auto interestOwedProxy = loan->at(sfInterestOwed);
    auto referencePrincipalProxy = loan->at(sfReferencePrincipal);

    TenthBips32 const interestRate{loan->at(sfInterestRate)};
    TenthBips32 const lateInterestRate{loan->at(sfLateInterestRate)};
    TenthBips32 const closeInterestRate{loan->at(sfCloseInterestRate)};
    TenthBips32 const overpaymentInterestRate{
        loan->at(sfOverpaymentInterestRate)};

    Number const serviceFee = loan->at(sfLoanServiceFee);
    Number const latePaymentFee = loan->at(sfLatePaymentFee);
    Number const closePaymentFee =
        roundToAsset(asset, loan->at(sfClosePaymentFee), loanScale);
    TenthBips32 const overpaymentFee{loan->at(sfOverpaymentFee)};

    auto const periodicPayment = loan->at(sfPeriodicPayment);

    auto prevPaymentDateProxy = loan->at(sfPreviousPaymentDate);
    std::uint32_t const startDate = loan->at(sfStartDate);

    std::uint32_t const paymentInterval = loan->at(sfPaymentInterval);
    // Compute the normal periodic rate, payment, etc.
    // We'll need it in the remaining calculations
    Number const periodicRate = loanPeriodicRate(interestRate, paymentInterval);
    XRPL_ASSERT(
        interestRate == 0 || periodicRate > 0,
        "ripple::loanMakePayment : valid rate");

    XRPL_ASSERT(
        *totalValueOutstandingProxy > 0,
        "ripple::loanMakePayment : valid total value");
    XRPL_ASSERT_PARTS(
        *interestOwedProxy >= 0,
        "ripple::loanMakePayment",
        "valid interest owed");

    view.update(loan);

    detail::PaymentComponentsPlus const periodic{
        detail::computePaymentComponents(
            asset,
            loanScale,
            totalValueOutstandingProxy,
            principalOutstandingProxy,
            referencePrincipalProxy,
            periodicPayment,
            periodicRate,
            paymentRemainingProxy),
        serviceFee};

    // -------------------------------------------------------------
    // late payment handling
    if (auto const latePaymentComponents = detail::handleLatePayment(
            asset,
            view,
            principalOutstandingProxy,
            *nextDueDateProxy,
            periodic,
            lateInterestRate,
            loanScale,
            latePaymentFee,
            amount,
            j))
    {
        return doPayment(
            *latePaymentComponents,
            totalValueOutstandingProxy,
            principalOutstandingProxy,
            referencePrincipalProxy,
            paymentRemainingProxy,
            prevPaymentDateProxy,
            nextDueDateProxy,
            paymentInterval);
    }
    else if (latePaymentComponents.error())
        // error() will be the TER returned if a payment is not made. It will
        // only evaluate to true if it's an error. Otherwise, tesSUCCESS means
        // nothing was done, so continue.
        return Unexpected(latePaymentComponents.error());

    // -------------------------------------------------------------
    // full payment handling
    auto const totalInterestOutstanding =
        totalValueOutstandingProxy - principalOutstandingProxy;

    if (auto const fullPaymentComponents = detail::handleFullPayment(
            asset,
            view,
            principalOutstandingProxy,
            referencePrincipalProxy,
            paymentRemainingProxy,
            prevPaymentDateProxy,
            startDate,
            paymentInterval,
            closeInterestRate,
            loanScale,
            totalInterestOutstanding,
            periodicRate,
            closePaymentFee,
            amount,
            j))
        return doPayment(
            *fullPaymentComponents,
            totalValueOutstandingProxy,
            principalOutstandingProxy,
            referencePrincipalProxy,
            paymentRemainingProxy,
            prevPaymentDateProxy,
            nextDueDateProxy,
            paymentInterval);
    else if (fullPaymentComponents.error())
        // error() will be the TER returned if a payment is not made. It will
        // only evaluate to true if it's an error. Otherwise, tesSUCCESS means
        // nothing was done, so continue.
        return Unexpected(fullPaymentComponents.error());

    // -------------------------------------------------------------
    // regular periodic payment handling

    // if the payment is not late nor if it's a full payment, then it must
    // be a periodic one, with possible overpayments

    // This will keep a running total of what is actually paid, if the payment
    // is sufficient for a single payment
    Number totalPaid =
        periodic.roundedInterest + periodic.roundedPrincipal + periodic.fee;

    if (amount < totalPaid)
    {
        JLOG(j.warn()) << "Periodic loan payment amount is insufficient. Due: "
                       << totalPaid << ", paid: " << amount;
        return Unexpected(tecINSUFFICIENT_PAYMENT);
    }

    LoanPaymentParts totalParts = detail::doPayment(
        periodic,
        totalValueOutstandingProxy,
        principalOutstandingProxy,
        referencePrincipalProxy,
        paymentRemainingProxy,
        prevPaymentDateProxy,
        nextDueDateProxy,
        paymentInterval);

    std::size_t numPayments = 1;

    while (totalPaid < amount && paymentRemainingProxy > 0)
    {
        // Try to make more payments
        detail::PaymentComponentsPlus const nextPayment{
            detail::computePaymentComponents(
                asset,
                loanScale,
                totalValueOutstandingProxy,
                principalOutstandingProxy,
                referencePrincipalProxy,
                periodicPayment,
                periodicRate,
                paymentRemainingProxy),
            periodic.fee};
        XRPL_ASSERT(
            nextPayment.rawInterest <= periodic.rawInterest,
            "ripple::loanMakePayment : decreasing interest");
        XRPL_ASSERT(
            nextPayment.rawPrincipal >= periodic.rawPrincipal,
            "ripple::loanMakePayment : increasing principal");

        // the fee part doesn't change
        auto const due = nextPayment.roundedInterest +
            nextPayment.roundedPrincipal + periodic.fee;

        if (amount < totalPaid + due)
            // We're done making payments.
            break;

        totalPaid += due;
        totalParts += detail::doPayment(
            nextPayment,
            totalValueOutstandingProxy,
            principalOutstandingProxy,
            referencePrincipalProxy,
            paymentRemainingProxy,
            prevPaymentDateProxy,
            nextDueDateProxy,
            paymentInterval);
        ++numPayments;
    }

    XRPL_ASSERT_PARTS(
        totalParts.principalPaid + totalParts.interestPaid == totalPaid,
        "ripple::loanMakePayment",
        "payment parts add up");
    XRPL_ASSERT_PARTS(
        totalParts.valueChange == 0,
        "ripple::loanMakePayment",
        "no value change");
    XRPL_ASSERT_PARTS(
        totalParts.feeToPay == periodic.fee * numPayments,
        "ripple::loanMakePayment",
        "fee parts add up");

    return Unexpected(temDISABLED);
#if LOANCOMPLETE
    // -------------------------------------------------------------
    // overpayment handling
    Number overpaymentInterestPortion = 0;
    if (loan->isFlag(lsfLoanOverpayment))
    {
        Number const overpayment = std::min(
            principalOutstandingProxy.value(),
            amount - (totalPrincipalPaid + totalInterestPaid + totalfeeToPay));

        if (roundToAsset(asset, overpayment, loanScale) > 0)
        {
            Number const interestPortion = roundToAsset(
                asset,
                tenthBipsOfValue(overpayment, overpaymentInterestRate),
                loanScale);
            Number const feePortion = roundToAsset(
                asset,
                tenthBipsOfValue(overpayment, overpaymentFee),
                loanScale);
            Number const remainder = roundToAsset(
                asset, overpayment - interestPortion - feePortion, loanScale);

            // Don't process an overpayment if the whole amount (or more!)
            // gets eaten by fees
            if (remainder > 0)
            {
                overpaymentInterestPortion = interestPortion;
                totalPrincipalPaid += remainder;
                totalInterestPaid += interestPortion;
                totalfeeToPay += feePortion;

                principalOutstandingProxy -= remainder;
            }
        }
    }

    totalParts.valueChange += (newTotalInterest - totalInterestOutstanding) +
        overpaymentInterestPortion;

    // Check the final results are rounded, to double-check that the
    // intermediate steps were rounded.
    XRPL_ASSERT(
        roundToAsset(asset, totalPrincipalPaid, loanScale) ==
            totalPrincipalPaid,
        "ripple::loanMakePayment : totalPrincipalPaid rounded");
    XRPL_ASSERT(
        roundToAsset(asset, totalInterestPaid, loanScale) == totalInterestPaid,
        "ripple::loanMakePayment : totalInterestPaid rounded");
    XRPL_ASSERT(
        roundToAsset(asset, loanValueChange, loanScale) == loanValueChange,
        "ripple::loanMakePayment : loanValueChange rounded");
    XRPL_ASSERT(
        roundToAsset(asset, totalfeeToPay, loanScale) == totalfeeToPay,
        "ripple::loanMakePayment : totalfeeToPay rounded");
    return LoanPaymentParts{
        .principalPaid = totalPrincipalPaid,
        .interestPaid = totalInterestPaid,
        .valueChange = loanValueChange,
        .feeToPay = totalfeeToPay};
#endif
}

}  // namespace ripple

#endif  // RIPPLE_APP_MISC_LENDINGHELPERS_H_INCLUDED
