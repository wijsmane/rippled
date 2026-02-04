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

namespace ripple {
namespace Risc0 {

//from libsnark
static uint256 generateRandomUint256()
{
    uint256 result;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::uint32_t> dis;

    for (int i = 0; i < 8; ++i)
    {
        std::uint32_t v = dis(gen);
        std::memcpy(result.begin() + i * 4, &v, 4);
    }
    return result;
}

//from libsnark
static std::string generateRandomSpendKey()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(100000, 999999);
    return "spend_key_" + std::to_string(dis(gen));
}

// map string -> uint256
static uint256 spendKeyFromString(std::string const& s)
{
    return sha512Half(makeSlice(s));
}


// private = amount(8) || rho(32) || r(32) || a_pk(32) || a_sk(32) => 136 bytes
static Blob pack_private(
    std::uint64_t amount,
    uint256 const& rho,
    uint256 const& r,
    uint256 const& a_pk,
    uint256 const& a_sk)
{
    Blob out;
    out.reserve(136);
    ripple::zkp::append_u64_be(out, amount);
    ripple::zkp::append_u256(out, rho);
    ripple::zkp::append_u256(out, r);
    ripple::zkp::append_u256(out, a_pk);
    ripple::zkp::append_u256(out, a_sk);
    return out;
}

class Risc0_test : public beast::unit_test::suite
{
public:
    void testProveNoteCommitmentNullifier()
    {
        std::uint64_t amount = 1000;

        uint256 rho  = generateRandomUint256();
        uint256 r    = generateRandomUint256();
        uint256 a_pk = generateRandomUint256();                 // recipient key
        uint256 a_sk = spendKeyFromString(generateRandomSpendKey()); // private spend key


        Blob priv_bytes = pack_private(amount, rho, r, a_pk, a_sk);

        // ensure bytes are packed correctly before trying to run the prover
        BEAST_EXPECT(priv_bytes.size() == 136);

        Risc0Bytes receipt = risc0_prove_zk_inputs(priv_bytes.data(), priv_bytes.size());

        BEAST_EXPECT(receipt.len > 0);

        if (receipt.ptr && receipt.len)
        {
            int const vrc = risc0_verify_receipt(receipt.ptr, receipt.len); // verify receipt (should technically be done by validators)
            BEAST_EXPECT(vrc == 0);

            Blob receipt_blob(receipt.ptr, receipt.ptr + receipt.len); // this would be to store the receipt in a transaction
            BEAST_EXPECT(!receipt_blob.empty());
        }

        Risc0Bytes journal = risc0_receipt_get_journal(receipt.ptr, receipt.len);
        BEAST_EXPECT(journal.ptr != nullptr);
        BEAST_EXPECT(journal.len == 64); // expect cm+nf (32 + 32)
        //std::cout << "Journal length: " << journal.len << std::endl;

        if (journal.ptr && journal.len) {
            risc0_free_bytes(journal.ptr, journal.len);
        }

        //free up the memory in rust because xrpl now has the receipt
        risc0_free_bytes(receipt.ptr, receipt.len);

    }

    void testTamperFails()
    {
        std::uint64_t amount = 1000;

        uint256 rho  = generateRandomUint256();
        uint256 r    = generateRandomUint256();
        uint256 a_pk = generateRandomUint256();
        uint256 a_sk = spendKeyFromString(generateRandomSpendKey());


        Blob priv_bytes = pack_private(amount, rho, r, a_pk, a_sk);

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

BEAST_DEFINE_TESTSUITE(Risc0, protocol, ripple);

}
}