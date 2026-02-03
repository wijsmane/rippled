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

// public = commitment(32) || nullifier(32) => 64 bytes
static Blob pack_public(uint256 const& commitment, uint256 const& nullifier)
{
    Blob out;
    out.reserve(64);
    ripple::zkp::append_u256(out, commitment);
    ripple::zkp::append_u256(out, nullifier);
    return out;
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

        ripple::zkp::ZkNote note{amount, rho, r, a_pk};

        // public values computed on host side to be used for comparison wimap string -> uint256th prover's output
        uint256 cm = ripple::zkp::computeCommitment(note);
        uint256 nf = ripple::zkp::computeNullifier(a_sk, note);

        Blob pub_bytes  = pack_public(cm, nf);
        Blob priv_bytes = pack_private(amount, rho, r, a_pk, a_sk);

        // ensure bytes are packed correctly before trying to run the prover
        BEAST_EXPECT(pub_bytes.size() == 64);
        BEAST_EXPECT(priv_bytes.size() == 136);

        int const rc = risc0_prove_zk_inputs(
            pub_bytes.data(), pub_bytes.size(),
            priv_bytes.data(), priv_bytes.size());

        BEAST_EXPECT(rc == 0);
    }

    void testTamperFails()
    {
        std::uint64_t amount = 1000;

        uint256 rho  = generateRandomUint256();
        uint256 r    = generateRandomUint256();
        uint256 a_pk = generateRandomUint256();
        uint256 a_sk = spendKeyFromString(generateRandomSpendKey());

        ripple::zkp::ZkNote note{amount, rho, r, a_pk};

        uint256 cm = ripple::zkp::computeCommitment(note);
        uint256 nf = ripple::zkp::computeNullifier(a_sk, note);

        Blob pub_bytes  = pack_public(cm, nf);
        Blob priv_bytes = pack_private(amount, rho, r, a_pk, a_sk);

        // flip one byte in commitment, guest should fail the equality check so the proving fails
        pub_bytes[0] ^= 0x01;

        int const rc = risc0_prove_zk_inputs(
            pub_bytes.data(), pub_bytes.size(),
            priv_bytes.data(), priv_bytes.size());

        BEAST_EXPECT(rc != 0);
    }

    void run() override
    {
        testProveNoteCommitmentNullifier();
        testTamperFails();
    }
};

BEAST_DEFINE_TESTSUITE(Risc0, protocol, ripple);

}
}