#include <test/jtx.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/digest.h>

#include <risc0-ffi.h>
#include <../include/xrpl/zkp/Note.h>

#include <cstring>
#include <string>

namespace ripple {
namespace test {

static void
append_u32_be(Blob& b, std::uint32_t v)
{
    b.push_back((v >> 24) & 0xFF);
    b.push_back((v >> 16) & 0xFF);
    b.push_back((v >>  8) & 0xFF);
    b.push_back((v >>  0) & 0xFF);
}

static uint256
makeBind(AccountID const& account, std::uint32_t seq)
{
    Blob b;
    b.reserve(20 + 4);
    b.insert(b.end(), account.begin(), account.end());
    append_u32_be(b, seq);
    return sha512Half(Slice(b.data(), b.size()));
}

class Risc0GuestHostMatch_test : public beast::unit_test::suite
{
public:
    void run() override
    {
        using namespace ripple;
        using namespace ripple::zkp;
        using namespace test::jtx;

        testcase("risc0 guest outputs match host reference computeCommitment/computeNullifier");

        uint256 const rho  = sha512Half(makeSlice(std::string("rho-test")));
        uint256 const r    = sha512Half(makeSlice(std::string("r-test")));
        uint256 const a_pk = sha512Half(makeSlice(std::string("a_pk-test")));
        uint256 const a_sk = sha512Half(makeSlice(std::string("a_sk-test")));

        std::uint64_t const amount = 123456789;

        Env env(*this);
        Account alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();

        std::uint32_t const seq = 1;
        uint256 const bind = makeBind(alice.id(), seq);

        ZkNote note(amount, rho, r, a_pk);

        uint256 const cm_ref = computeCommitment(note, bind);
        uint256 const nf_ref = computeNullifier(a_sk, note);

        BEAST_EXPECT(cm_ref != beast::zero);
        BEAST_EXPECT(nf_ref != beast::zero);

        Blob const witness = packWitness(note, a_sk, bind);
        BEAST_EXPECT(witness.size() == 168);

        Risc0Bytes receipt = risc0_prove_zk_inputs(witness.data(), witness.size());
        BEAST_EXPECT(receipt.ptr && receipt.len);

        int const vrc = risc0_verify_receipt(receipt.ptr, receipt.len);
        BEAST_EXPECT(vrc == 0);

        Risc0Bytes journal = risc0_receipt_get_journal(receipt.ptr, receipt.len);
        BEAST_EXPECT(journal.ptr != nullptr);
        BEAST_EXPECT(journal.len == 64);

        uint256 cm_guest, nf_guest;
        std::memcpy(cm_guest.begin(), journal.ptr, 32);
        std::memcpy(nf_guest.begin(),
                    static_cast<std::uint8_t const*>(journal.ptr) + 32,
                    32);

        BEAST_EXPECT(cm_guest == cm_ref);
        BEAST_EXPECT(nf_guest == nf_ref);

        if (journal.ptr && journal.len)
            risc0_free_bytes(const_cast<std::uint8_t*>(journal.ptr), journal.len);
        if (receipt.ptr && receipt.len)
            risc0_free_bytes(const_cast<std::uint8_t*>(receipt.ptr), receipt.len);
    }
};

BEAST_DEFINE_TESTSUITE(Risc0GuestHostMatch, zkp, ripple);

} // namespace test
} // namespace ripple