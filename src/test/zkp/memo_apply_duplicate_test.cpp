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
#include <../include/xrpl/zkp/Note.h>  // append_u64_be, append_u256

#include <optional>
#include <random>
#include <cstring>

namespace ripple {
namespace test {

// from libsnark to generate random values
static uint256
randomUint256()
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

static uint256
spendKeyFromString(std::string const& s)
{
    return sha512Half(makeSlice(s));
}

//get hex representation for storing in memo
static std::string
hex256(uint256 const& u)
{
    return strHex(u.begin(), u.end());
}

//get current account sequence number to use in the bind
static std::uint32_t
currentAccountSequence(test::jtx::Env& env, test::jtx::Account const& acct)
{
    auto const sle = env.le(keylet::account(acct.id()));
    if (!sle)
        return 0;
    return sle->getFieldU32(sfSequence);
}

static void
append_u32_be(Blob& b, std::uint32_t v)
{
    b.push_back((v >> 24) & 0xFF);
    b.push_back((v >> 16) & 0xFF);
    b.push_back((v >>  8) & 0xFF);
    b.push_back((v >>  0) & 0xFF);
}

//build bind to make sure that even if someone copies cm,nf from memo,
// the proof computation of cm is tied to the transaction
static uint256
makeBind(AccountID const& account, std::uint32_t seq)
{
    Blob b;
    b.reserve(20 + 4);

    b.insert(b.end(), account.begin(), account.end());

    append_u32_be(b, seq);

    return sha512Half(Slice(b.data(), b.size()));
}


// witness = amount(8) || rho(32) || r(32) || a_pk(32) || a_sk(32) || bind(32)
static Blob
pack_private(
    std::uint64_t amount,
    uint256 const& rho,
    uint256 const& r,
    uint256 const& a_pk,
    uint256 const& a_sk,
    uint256 const& bind)
{
    Blob out;
    out.reserve(168);
    ripple::zkp::append_u64_be(out, amount);
    ripple::zkp::append_u256(out, rho);
    ripple::zkp::append_u256(out, r);
    ripple::zkp::append_u256(out, a_pk);
    ripple::zkp::append_u256(out, a_sk);
    ripple::zkp::append_u256(out, bind);
    return out;
}

// retrieve cm and nf (public outputs) from journal
static std::pair<uint256, uint256>
parseJournalCmNf(Risc0Bytes const& journal)
{
    uint256 cm, nf;
    if (!journal.ptr || journal.len != 64)
        return {uint256{}, uint256{}};

    std::memcpy(cm.begin(), journal.ptr, 32);
    std::memcpy(nf.begin(), static_cast<std::uint8_t const*>(journal.ptr) + 32, 32);
    return {cm, nf};
}

// attach memo with MemoType="zkp", MemoFormat="cmnf-v1", MemoData = hex(cm)||hex(nf)
static void
attachZkpMemo(test::jtx::JTx& jt, uint256 const& cm, uint256 const& nf)
{
    Json::Value memo(Json::objectValue);
    memo[sfMemoType.jsonName]   = strHex(std::string_view("zkp"));
    memo[sfMemoFormat.jsonName] = strHex(std::string_view("cmnf-v1"));
    memo[sfMemoData.jsonName]   = hex256(cm) + hex256(nf); // have to convert to hex

    Json::Value wrap(Json::objectValue);
    wrap[sfMemo.jsonName] = memo;

    Json::Value memos(Json::arrayValue);
    memos.append(wrap);

    jt.jv[sfMemos.jsonName] = memos;
}

// extract first Memo STObject from applied STTx and check that it is valid
// sfMemos is an STArray where each element contains an sfMemo
static std::optional<STObject>
firstMemoObject(std::shared_ptr<STTx const> const& tx)
{
    if (!tx || !tx->isFieldPresent(sfMemos))
        return std::nullopt;

    auto const& memosArr = tx->getFieldArray(sfMemos);
    if (memosArr.empty())
        return std::nullopt;

    auto const& item = memosArr[0];

    if (item.isFieldPresent(sfMemo))
        return item.getFieldObject(sfMemo); // copy out
    return item; // copy out
}

class Risc0MemoApplyDuplicate_test : public beast::unit_test::suite
{
public:
    void
    testRisc0JournalToMemoToLedgerAndDuplicate()
    {
        testcase("risc0: prove -> journal(cm||nf) -> memo -> doApply inserts entries; duplicate nf => tecDUPLICATE");

        using namespace test::jtx;

        //create a funded account
        Account alice{"alice"};
        Env env(*this);
        env.fund(XRP(10000), alice);
        env.close(); //advance the ledger so the new state is finalised

        //generate values for first transaction
        uint256 const rho  = randomUint256();                
        uint256 const a_sk = spendKeyFromString("spend_key_123456"); 

        std::uint64_t const amount1 = 1000;
        uint256 const r1    = randomUint256();
        uint256 const a_pk1 = randomUint256();

        std::cout<< "generated private inputs\n" <<std::endl;

        //retrieve sequence number so we can bind to the current sequence
        std::uint32_t const seq1 = currentAccountSequence(env, alice);
        BEAST_EXPECT(seq1 != 0);

        uint256 const bind1 = makeBind(alice.id(), seq1);

        std::cout<<"bound inputs to this tx\n"<<std::endl;

        //put all private inputs together to send to prover as the witness
        Blob const witness1 = pack_private(amount1, rho, r1, a_pk1, a_sk, bind1);
        BEAST_EXPECT(witness1.size() == 168);
        std::cout<<"packed bytes to send to Risc0 prover, now generating proof\n"<<std::endl;

        //generate proof
        Risc0Bytes receipt1 = risc0_prove_zk_inputs(witness1.data(), witness1.size());
        BEAST_EXPECT(receipt1.ptr && receipt1.len);
        std::cout<<"proof generated successfully\n"<<std::endl;

        //verify proof
        int const vrc1 = risc0_verify_receipt(receipt1.ptr, receipt1.len);
        BEAST_EXPECT(vrc1 == 0);
        std::cout<<"receipt verified\n"<<std::endl;

        //get public output
        Risc0Bytes journal1 = risc0_receipt_get_journal(receipt1.ptr, receipt1.len);
        BEAST_EXPECT(journal1.ptr != nullptr);
        BEAST_EXPECT(journal1.len == 64);
        std::cout << "journal processed successfully\n" << std::endl;

        //get commitment and nullifier
        auto const [cm1, nf] = parseJournalCmNf(journal1);
        BEAST_EXPECT(cm1 != beast::zero); 
        BEAST_EXPECT(nf != beast::zero);
        std::cout << "committment and nullifier retrieved\n" << std::endl;

        //build tx with memo carrying prover outputs
        std::cout << "building transaction with memo carrying prover outputs (cm and nf)\n" << std::endl;
        JTx jt = noop(alice);
        attachZkpMemo(jt, cm1, nf);
        env(jt);
        env.close();


        // confirm memo decodes to EXACT bytes used
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

                BEAST_EXPECT(dataHex == (hex256(cm1) + hex256(nf)));
            }
        }
    

        //check ledger entries

        //look up the nullifier and commitment entries in the current open ledger view
        auto const nfSle = env.le(keylet::zkNullifier(nf)); 
        auto const cmSle = env.le(keylet::zkCommitment(cm1));
        //make sure they are not null (were actually inserted)
        BEAST_EXPECT(nfSle != nullptr);
        BEAST_EXPECT(cmSle != nullptr);

        //just double check that they are the right entry types
        if (nfSle)
            BEAST_EXPECT(nfSle->getType() == ltZK_NULLIFIER);
        if (cmSle)
            BEAST_EXPECT(cmSle->getType() == ltZK_COMMITMENT);
        std::cout << "nullifier and commitment ledger entries were inserted successfully\n" << std::endl;
        

        //second tx to test duplicate nullifier handling
        std::cout << "creating second transction with same nullifier (same rho and a_sk)\n" << std::endl;
        std::uint64_t const amount2 = 2000;
        uint256 const r2    = randomUint256();
        uint256 const a_pk2 = randomUint256();

        std::uint32_t const seq2 = currentAccountSequence(env, alice);
        uint256 const bind2 = makeBind(alice.id(), seq2);

        Blob const witness2 = pack_private(amount2, rho, r2, a_pk2, a_sk, bind2);
        BEAST_EXPECT(witness2.size() == 168);

        Risc0Bytes receipt2 = risc0_prove_zk_inputs(witness2.data(), witness2.size());
        BEAST_EXPECT(receipt2.ptr && receipt2.len);

        int const vrc2 = risc0_verify_receipt(receipt2.ptr, receipt2.len);
        BEAST_EXPECT(vrc2 == 0);

        Risc0Bytes journal2 = risc0_receipt_get_journal(receipt2.ptr, receipt2.len);
        BEAST_EXPECT(journal2.ptr != nullptr);
        BEAST_EXPECT(journal2.len == 64);

        auto const [cm2, nf2] = parseJournalCmNf(journal2);

        // Because rho and a_sk are the same, nf should match (guest must NOT include bind in nf)
        BEAST_EXPECT(nf2 == nf);
        std::cout << "nf2 was retrieved from journal and matches nf as expected due to same rho and a_sk\n" << std::endl;

        // submit should reject as duplicate nullifier
        std::cout << "attempting to submit the transaction\n" << std::endl;
        JTx jt2 = noop(alice);
        attachZkpMemo(jt2, cm2, nf2);
        env(jt2, ter(tecDUPLICATE));
        env.close();
        
        std::cout << "confirming cm2 was NOT inserted and nf is still present\n" << std::endl;
        BEAST_EXPECT(env.le(keylet::zkNullifier(nf)) != nullptr); //nullifier still there
        BEAST_EXPECT(env.le(keylet::zkCommitment(cm2)) == nullptr); //cm2 not there
        BEAST_EXPECT(env.le(keylet::zkCommitment(cm1)) != nullptr);// cm1 still there
        

        //free FFI allocations
        if (journal1.ptr && journal1.len) risc0_free_bytes(const_cast<std::uint8_t*>(journal1.ptr), journal1.len);
        if (receipt1.ptr && receipt1.len) risc0_free_bytes(const_cast<std::uint8_t*>(receipt1.ptr), receipt1.len);
        if (journal2.ptr && journal2.len) risc0_free_bytes(const_cast<std::uint8_t*>(journal2.ptr), journal2.len);
        if (receipt2.ptr && receipt2.len) risc0_free_bytes(const_cast<std::uint8_t*>(receipt2.ptr), receipt2.len);
    }

    void
    run() override
    {
        testRisc0JournalToMemoToLedgerAndDuplicate();
    }
};

BEAST_DEFINE_TESTSUITE(Risc0MemoApplyDuplicate, zkp, ripple);

} // namespace test
} // namespace ripple
