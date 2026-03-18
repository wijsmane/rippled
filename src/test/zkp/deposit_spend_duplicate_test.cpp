#include <test/jtx.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/basics/base_uint.h>

#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Keylet.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/digest.h>

#include <risc0-ffi.h>
#include <../include/xrpl/zkp/Note.h>
#include "test_helpers.h"

#include <optional>
#include <random>
#include <cstring>

namespace ripple {
namespace test {

class DepositSpendDuplicate_test : public beast::unit_test::suite
{
public:
    void
    testDepositThenSpendThenDuplicateSpend()
    {
        testcase("risc0: deposit creates commitment, spend creates nullifier, duplicate spend rejected");

        using namespace test::jtx;

        Account alice{"alice"};
        Env env(*this);
        env.fund(XRP(10000), alice);
        env.close();

        // test 1: create note and deposit it
        uint256 const rho  = generateRandomUint256();
        uint256 const r1   = generateRandomUint256();
        uint256 const a_pk = generateRandomUint256();
        uint256 const a_sk = spendKeyFromString("spend_key_123456");
        std::uint64_t const amount = 1000;

        std::cout << "generated witness inputs\n" << std::endl;

        ripple::zkp::ZkNote note1(amount, rho, r1, a_pk);

        Blob const witnessDeposit = ripple::zkp::packWitnessDeposit(note1);
        BEAST_EXPECT(witnessDeposit.size() == 105);

        Risc0Bytes receiptDeposit =
            risc0_prove_zk_inputs(witnessDeposit.data(), witnessDeposit.size());
        BEAST_EXPECT(receiptDeposit.ptr && receiptDeposit.len);

        std::cout << "generated deposit proof. length is " << receiptDeposit.len << "\n" << std::endl;


        int const verifyDeposit =
            risc0_verify_receipt(receiptDeposit.ptr, receiptDeposit.len);
        BEAST_EXPECT(verifyDeposit == 0);

        Risc0Bytes journalDeposit =
            risc0_receipt_get_journal(receiptDeposit.ptr, receiptDeposit.len);
        BEAST_EXPECT(journalDeposit.ptr != nullptr);
        BEAST_EXPECT(journalDeposit.len == 33);

        auto cmOpt = parseJournalDepositCm(journalDeposit);
        BEAST_EXPECT(cmOpt.has_value());

        uint256 const cm1 = *cmOpt;
        BEAST_EXPECT(cm1 != beast::zero);

        JTx jtDeposit = noop(alice);
        attachZkpMemoDeposit(jtDeposit, cm1);
        env(jtDeposit);
        env.close();

        // Confirm memo bytes
        {
            auto tx = env.tx();
            BEAST_EXPECT(tx);
            if (tx)
            {
                auto memoOpt = firstMemoObject(tx);
                BEAST_EXPECT(memoOpt.has_value());
                if (memoOpt)
                {
                    auto const& memoObj = *memoOpt;
                    BEAST_EXPECT(memoObj.isFieldPresent(sfMemoData));

                    auto const dataBlob = memoObj.getFieldVL(sfMemoData);
                    BEAST_EXPECT(dataBlob.size() == 32);

                    std::string const dataHex =
                        strHex(Slice(dataBlob.data(), dataBlob.size()));

                    BEAST_EXPECT(dataHex == hex256(cm1));
                }
            }
        }

        std::cout << "submit deposit tx\n" << std::endl;

        // Ledger should contain commitment after deposit
        {
            auto const cmSle = env.le(keylet::zkCommitment(cm1));
            BEAST_EXPECT(cmSle != nullptr);
            if (cmSle)
                BEAST_EXPECT(cmSle->getType() == ltZK_COMMITMENT);
        }

        // test2: spend this note

        Blob const witnessSpend = ripple::zkp::packWitnessSpend(note1, a_sk);
        BEAST_EXPECT(witnessSpend.size() == 137);

        std::cout << "packed spend witness\n" << std::endl;

        Risc0Bytes receiptSpend =
            risc0_prove_zk_inputs(witnessSpend.data(), witnessSpend.size());
        BEAST_EXPECT(receiptSpend.ptr && receiptSpend.len);

        std::cout << "generated spend proof. length is " << receiptSpend.len << "\n" << std::endl;

        int const verifySpend =
            risc0_verify_receipt(receiptSpend.ptr, receiptSpend.len);
        BEAST_EXPECT(verifySpend == 0);

        Risc0Bytes journalSpend =
            risc0_receipt_get_journal(receiptSpend.ptr, receiptSpend.len);
        BEAST_EXPECT(journalSpend.ptr != nullptr);
        BEAST_EXPECT(journalSpend.len == 65);

        auto spendOpt = parseJournalSpendCmNf(journalSpend);
        BEAST_EXPECT(spendOpt.has_value());

        auto const [cmOld, nf1] = *spendOpt;
        BEAST_EXPECT(cmOld != beast::zero);
        BEAST_EXPECT(nf1 != beast::zero);

        //spend must refer to the deposited note
        BEAST_EXPECT(cmOld == cm1);

        JTx jtSpend = noop(alice);
        attachZkpMemoSpend(jtSpend, cmOld, nf1);
        env(jtSpend);
        env.close();

        // Confirm memo bytes
        {
            auto tx = env.tx();
            BEAST_EXPECT(tx);
            if (tx)
            {
                auto memoOpt = firstMemoObject(tx);
                BEAST_EXPECT(memoOpt.has_value());
                if (memoOpt)
                {
                    auto const& memoObj = *memoOpt;
                    BEAST_EXPECT(memoObj.isFieldPresent(sfMemoData));

                    auto const dataBlob = memoObj.getFieldVL(sfMemoData);
                    BEAST_EXPECT(dataBlob.size() == 64);

                    std::string const dataHex =
                        strHex(Slice(dataBlob.data(), dataBlob.size()));

                    BEAST_EXPECT(dataHex == (hex256(cmOld) + hex256(nf1)));
                }
            }
        }

        std::cout << "checking ledger updates\n" << std::endl;
        // Ledger after spend:
        // - nullifier should exist
        // - commitment should exist
        {
            auto const nfSle = env.le(keylet::zkNullifier(nf1));
            BEAST_EXPECT(nfSle != nullptr);
            if (nfSle)
                BEAST_EXPECT(nfSle->getType() == ltZK_NULLIFIER);

            auto const cmSle = env.le(keylet::zkCommitment(cmOld));
            BEAST_EXPECT(cmSle != nullptr);
            if (cmSle)
                BEAST_EXPECT(cmSle->getType() == ltZK_COMMITMENT);
        }

        // test 3: duplicate spend of same note - should fail

        JTx jtSpendDup = noop(alice);
        attachZkpMemoSpend(jtSpendDup, cmOld, nf1);
        env(jtSpendDup, ter(tecDUPLICATE)); 
        env.close();

        std::cout << "checking ledger for duplicate spend\n" << std::endl;
        // Nullifier should still exist
        BEAST_EXPECT(env.le(keylet::zkNullifier(nf1)) != nullptr);

        if (journalDeposit.ptr && journalDeposit.len)
            risc0_free_bytes(const_cast<std::uint8_t*>(journalDeposit.ptr), journalDeposit.len);
        if (receiptDeposit.ptr && receiptDeposit.len)
            risc0_free_bytes(const_cast<std::uint8_t*>(receiptDeposit.ptr), receiptDeposit.len);

        if (journalSpend.ptr && journalSpend.len)
            risc0_free_bytes(const_cast<std::uint8_t*>(journalSpend.ptr), journalSpend.len);
        if (receiptSpend.ptr && receiptSpend.len)
            risc0_free_bytes(const_cast<std::uint8_t*>(receiptSpend.ptr), receiptSpend.len);

    }

    void
    run() override
    {
        testDepositThenSpendThenDuplicateSpend();
    }
};

BEAST_DEFINE_TESTSUITE(DepositSpendDuplicate, zkp, ripple);

} // namespace test
} // namespace ripple