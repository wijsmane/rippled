#include <test/jtx.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/base_uint.h>

#include <risc0-ffi.h>
#include <../include/xrpl/zkp/Note.h>
#include "test_helpers.h"

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <string>

namespace ripple {
namespace test {

namespace {

struct Risc0BytesGuard
{
    Risc0Bytes bytes{nullptr, 0};

    ~Risc0BytesGuard()
    {
        if (bytes.ptr && bytes.len)
        {
            risc0_free_bytes(
                const_cast<std::uint8_t*>(bytes.ptr), bytes.len);
        }
    }

    Risc0BytesGuard() = default;
    Risc0BytesGuard(Risc0BytesGuard const&) = delete;
    Risc0BytesGuard& operator=(Risc0BytesGuard const&) = delete;
};

double
msBetween(
    std::chrono::steady_clock::time_point const& start,
    std::chrono::steady_clock::time_point const& end)
{
    return std::chrono::duration<double, std::milli>(end - start).count();
}

}  // namespace

class ProofTiming_test : public beast::unit_test::suite
{
public:
    void
    testProofTimings()
    {
        testcase("proof timing csv");

        std::string const csvPath = "zkp_proof_timing.csv";
        std::ofstream csv(csvPath, std::ios::out | std::ios::trunc);
        BEAST_EXPECT(csv.is_open());
        if (!csv.is_open())
            return;

        csv << "kind,iteration,witness_bytes,receipt_bytes,journal_bytes,"
               "prove_ms,verify_ms,journal_ms\n";
        csv << std::fixed << std::setprecision(3);

        std::uint64_t const amountBase = 1000;
        uint256 const a_sk = spendKeyFromString("proof_timing_spend_key");

        for (int i = 0; i < 5; ++i)
        {
            std::cout<<"deposit proof " << i << std::endl;
            uint256 const rho  = generateRandomUint256();
            uint256 const r    = generateRandomUint256();
            uint256 const a_pk = generateRandomUint256();

            ripple::zkp::ZkNote note(amountBase + i, rho, r, a_pk);

            Blob const witness = ripple::zkp::packWitnessDeposit(note);
            BEAST_EXPECT(witness.size() == 105);

            Risc0BytesGuard receipt;
            Risc0BytesGuard journal;

            auto const proveStart = std::chrono::steady_clock::now();
            receipt.bytes =
                risc0_prove_zk_inputs(witness.data(), witness.size());
            auto const proveEnd = std::chrono::steady_clock::now();

            BEAST_EXPECT(receipt.bytes.ptr && receipt.bytes.len);
            if (!(receipt.bytes.ptr && receipt.bytes.len))
                return;

            auto const verifyStart = std::chrono::steady_clock::now();
            int const verifyRc =
                risc0_verify_receipt(receipt.bytes.ptr, receipt.bytes.len);
            auto const verifyEnd = std::chrono::steady_clock::now();

            BEAST_EXPECT(verifyRc == 0);
            if (verifyRc != 0)
                return;

            auto const journalStart = std::chrono::steady_clock::now();
            journal.bytes =
                risc0_receipt_get_journal(receipt.bytes.ptr, receipt.bytes.len);
            auto const journalEnd = std::chrono::steady_clock::now();

            BEAST_EXPECT(journal.bytes.ptr != nullptr);
            BEAST_EXPECT(journal.bytes.len == 33);
            if (!(journal.bytes.ptr && journal.bytes.len == 33))
                return;

            auto const cmOpt = parseJournalDepositCm(journal.bytes);
            BEAST_EXPECT(cmOpt.has_value());
            if (!cmOpt)
                return;

            csv << "deposit"
                << "," << i
                << "," << witness.size()
                << "," << receipt.bytes.len
                << "," << journal.bytes.len
                << "," << msBetween(proveStart, proveEnd)
                << "," << msBetween(verifyStart, verifyEnd)
                << "," << msBetween(journalStart, journalEnd)
                << "\n";
        }

        for (int i = 0; i < 5; ++i)
        {
            std::cout<<"spend proof " << i << std::endl;
            uint256 const rho  = generateRandomUint256();
            uint256 const r    = generateRandomUint256();
            uint256 const a_pk = generateRandomUint256();

            ripple::zkp::ZkNote note(amountBase + 100 + i, rho, r, a_pk);

            Blob const witness = ripple::zkp::packWitnessSpend(note, a_sk);
            BEAST_EXPECT(witness.size() == 137);

            Risc0BytesGuard receipt;
            Risc0BytesGuard journal;

            auto const proveStart = std::chrono::steady_clock::now();
            receipt.bytes =
                risc0_prove_zk_inputs(witness.data(), witness.size());
            auto const proveEnd = std::chrono::steady_clock::now();

            BEAST_EXPECT(receipt.bytes.ptr && receipt.bytes.len);
            if (!(receipt.bytes.ptr && receipt.bytes.len))
                return;

            auto const verifyStart = std::chrono::steady_clock::now();
            int const verifyRc =
                risc0_verify_receipt(receipt.bytes.ptr, receipt.bytes.len);
            auto const verifyEnd = std::chrono::steady_clock::now();

            BEAST_EXPECT(verifyRc == 0);
            if (verifyRc != 0)
                return;

            auto const journalStart = std::chrono::steady_clock::now();
            journal.bytes =
                risc0_receipt_get_journal(receipt.bytes.ptr, receipt.bytes.len);
            auto const journalEnd = std::chrono::steady_clock::now();

            BEAST_EXPECT(journal.bytes.ptr != nullptr);
            BEAST_EXPECT(journal.bytes.len == 65);
            if (!(journal.bytes.ptr && journal.bytes.len == 65))
                return;

            auto const spendOpt = parseJournalSpendCmNf(journal.bytes);
            BEAST_EXPECT(spendOpt.has_value());
            if (!spendOpt)
                return;

            csv << "spend"
                << "," << i
                << "," << witness.size()
                << "," << receipt.bytes.len
                << "," << journal.bytes.len
                << "," << msBetween(proveStart, proveEnd)
                << "," << msBetween(verifyStart, verifyEnd)
                << "," << msBetween(journalStart, journalEnd)
                << "\n";
        }

        csv.flush();
        BEAST_EXPECT(csv.good());
        log << "wrote proof timing CSV to " << csvPath;
    }

    void
    run() override
    {
        testProofTimings();
    }
};

BEAST_DEFINE_TESTSUITE(ProofTiming, zkp, ripple);

}  // namespace test
}  // namespace ripple