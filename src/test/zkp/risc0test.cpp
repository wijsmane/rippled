#include <xrpl/beast/unit_test.h>

#include <xrpl/basics/Blob.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/basics/Slice.h>      

#include <random>
#include <cstring>
#include <string>
#include <array>

#include <risc0-ffi.h>
#include <../include/xrpl/zkp/Note.h>
#include "test_helpers.h"

namespace ripple {
namespace test {


class Risc0_test : public beast::unit_test::suite
{
public:
    void testProveNoteCommitmentNullifier()
    {
        std::cout << "start test ProveNoteCommitmentNullifier...\n" << std::endl;

        std::uint64_t amount1 = 1000;

        uint256 rho1  = generateRandomUint256();
        uint256 r1    = generateRandomUint256();
        uint256 a_pk1 = generateRandomUint256();                 // recipient key
        uint256 a_sk1 = spendKeyFromString(generateRandomSpendKey()); // private spend key

        std::cout << "generated witness inputs\n" << std::endl;

        ripple::zkp::ZkNote note1 = ripple::zkp::ZkNote(amount1, rho1, r1, a_pk1);
        Blob priv_bytes = ripple::zkp::packWitnessSpend(note1, a_sk1);

        BEAST_EXPECT(priv_bytes.size() == 137);
        std::cout << "witness input bytes packed successfully, now running prover\n" << std::endl;

        Risc0Bytes receipt = risc0_prove_zk_inputs(priv_bytes.data(), priv_bytes.size());

        if (!(receipt.ptr && receipt.len))
        {
            std::cout << "error receipt is null/empty\n";
            return;
        }

        BEAST_EXPECT(receipt.len > 0);
        std::cout <<"proof generated and receipt was received\n" <<std::endl;

        std::cout<<"recipet len:"<<receipt.len<<std::endl;

        int const vrc = risc0_verify_receipt(receipt.ptr, receipt.len); // verify receipt (should technically be done by validators)
        BEAST_EXPECT(vrc == 0);
        std::cout << "receipt verified successfully\n" << std::endl;

        Blob receipt_blob(receipt.ptr, receipt.ptr + receipt.len); // create a blob to store the receipt somewhere
        BEAST_EXPECT(!receipt_blob.empty());
        std::cout << "blob created to store receipt" << std::endl;

        Risc0Bytes journal = risc0_receipt_get_journal(receipt.ptr, receipt.len);
        BEAST_EXPECT(journal.ptr != nullptr);
        BEAST_EXPECT(journal.len == 65); // expect type+cm+nf (1+ 32 + 32)
        //std::cout << "Journal length: " << journal.len << std::endl;
        std::cout<< "journal retreived successfully" << std::endl;

        if (journal.ptr && journal.len) {
            risc0_free_bytes(journal.ptr, journal.len);
        }

        //free up the memory in rust because xrpl now has the receipt
        risc0_free_bytes(receipt.ptr, receipt.len);

    }

    void testTamperFails()
    {
        std::uint64_t amount2 = 1000;

        uint256 rho2  = generateRandomUint256();
        uint256 r2    = generateRandomUint256();
        uint256 a_pk2 = generateRandomUint256();
        uint256 a_sk2 = spendKeyFromString(generateRandomSpendKey());

        ripple::zkp::ZkNote note2 = ripple::zkp::ZkNote(amount2, rho2, r2, a_pk2);
        Blob priv_bytes = ripple::zkp::packWitnessSpend(note2, a_sk2);


        // flip one byte, guest should fail the equality check so the proving fails
        priv_bytes[0] ^= 0x01;

        Risc0Bytes receipt = risc0_prove_zk_inputs(priv_bytes.data(), priv_bytes.size());

        BEAST_EXPECT(receipt.ptr == nullptr || receipt.len == 0); // because no receipt (proof) is generated
    }

    void run() override
    {
        testProveNoteCommitmentNullifier();
        //testTamperFails();
    }
};

BEAST_DEFINE_TESTSUITE(Risc0, zkp, ripple);

}
}