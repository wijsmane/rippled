#include <test/jtx.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/Keylet.h>

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

double
msBetween(
    std::chrono::steady_clock::time_point const& start,
    std::chrono::steady_clock::time_point const& end)
{
    return std::chrono::duration<double, std::milli>(end - start).count();
}

}  // namespace

class ApplyTimingNoProof_test : public beast::unit_test::suite
{
public:
    void
    testApplyTimingsNoProof()
    {
        testcase("transaction apply timing csv without proof generation");

        using namespace test::jtx;

        std::string const csvPath = "zkp_apply_timing.csv";
        std::ofstream csv(csvPath, std::ios::out | std::ios::trunc);
        BEAST_EXPECT(csv.is_open());
        if (!csv.is_open())
            return;

        csv << "kind,iteration,submit_ms,close_ms,total_ms\n";
        csv << std::fixed << std::setprecision(3);

        Account alice{"alice"};
        Env env(*this);
        env.fund(XRP(100000), alice);
        env.close();

        uint256 const a_sk = spendKeyFromString("apply_timing_spend_key");

        //time normal noop tx
        for (int i = 0; i < 50; ++i)
        {
            JTx jt = noop(alice);

            auto const submitStart = std::chrono::steady_clock::now();
            env(jt);
            auto const submitEnd = std::chrono::steady_clock::now();

            auto const closeStart = std::chrono::steady_clock::now();
            env.close();
            auto const closeEnd = std::chrono::steady_clock::now();

            csv << "normal"
                << "," << i
                << "," << msBetween(submitStart, submitEnd)
                << "," << msBetween(closeStart, closeEnd)
                << "," << msBetween(submitStart, closeEnd)
                << "\n";
        }

        //time deposit tx
        for (int i = 0; i < 50; ++i)
        {
            uint256 const rho  = generateRandomUint256();
            uint256 const r    = generateRandomUint256();
            uint256 const a_pk = generateRandomUint256();

            ripple::zkp::ZkNote note(2000 + i, rho, r, a_pk);

            uint256 const cm = ripple::zkp::computeCommitment(note);

            JTx jt = noop(alice);
            attachZkpMemoDeposit(jt, cm);

            auto const submitStart = std::chrono::steady_clock::now();
            env(jt);
            auto const submitEnd = std::chrono::steady_clock::now();

            auto const closeStart = std::chrono::steady_clock::now();
            env.close();
            auto const closeEnd = std::chrono::steady_clock::now();

            csv << "zk_deposit"
                << "," << i
                << "," << msBetween(submitStart, submitEnd)
                << "," << msBetween(closeStart, closeEnd)
                << "," << msBetween(submitStart, closeEnd)
                << "\n";

            BEAST_EXPECT(env.le(keylet::zkCommitment(cm)) != nullptr);
        }

        //time spend tx
        for (int i = 0; i < 50; ++i)
        {
            uint256 const rho  = generateRandomUint256();
            uint256 const r    = generateRandomUint256();
            uint256 const a_pk = generateRandomUint256();

            ripple::zkp::ZkNote note(3000 + i, rho, r, a_pk);

            uint256 const cmOld = ripple::zkp::computeCommitment(note);
            uint256 const nf    = ripple::zkp::computeNullifier(a_sk, note);

            // Setup deposit first (not timed)
            {
                JTx jtDeposit = noop(alice);
                attachZkpMemoDeposit(jtDeposit, cmOld);
                env(jtDeposit);
                env.close();

                BEAST_EXPECT(env.le(keylet::zkCommitment(cmOld)) != nullptr);
            }

            // Timed spend
            JTx jtSpend = noop(alice);
            attachZkpMemoSpend(jtSpend, cmOld, nf);

            auto const submitStart = std::chrono::steady_clock::now();
            env(jtSpend);
            auto const submitEnd = std::chrono::steady_clock::now();

            auto const closeStart = std::chrono::steady_clock::now();
            env.close();
            auto const closeEnd = std::chrono::steady_clock::now();

            csv << "zk_spend"
                << "," << i
                << "," << msBetween(submitStart, submitEnd)
                << "," << msBetween(closeStart, closeEnd)
                << "," << msBetween(submitStart, closeEnd)
                << "\n";

            BEAST_EXPECT(env.le(keylet::zkNullifier(nf)) != nullptr);
            BEAST_EXPECT(env.le(keylet::zkCommitment(cmOld)) == nullptr);
        }

        csv.flush();
        BEAST_EXPECT(csv.good());
        log << "wrote apply timing CSV to " << csvPath;
    }

    void
    run() override
    {
        testApplyTimingsNoProof();
    }
};

BEAST_DEFINE_TESTSUITE(ApplyTimingNoProof, zkp, ripple);

}  // namespace test
}  // namespace ripple