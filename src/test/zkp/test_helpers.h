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

#include <optional>
#include <random>
#include <cstring>
#include <utility>

namespace ripple {
namespace test {

static constexpr std::uint8_t kModeDeposit = 1;
static constexpr std::uint8_t kModeSpend   = 2;

// from libsnark
static uint256
generateRandomUint256()
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

// from libsnark
static std::string
generateRandomSpendKey()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(100000, 999999);
    return "spend_key_" + std::to_string(dis(gen));
}

// map string -> uint256
static uint256
spendKeyFromString(std::string const& s)
{
    return sha512Half(makeSlice(s));
}

// get hex representation for storing in memo
static std::string
hex256(uint256 const& u)
{
    return strHex(u.begin(), u.end());
}

static void
attachMemo(test::jtx::JTx& jt,
           std::string_view memoType,
           std::string_view memoFormat,
           std::string const& memoDataHex)
{
    Json::Value memo(Json::objectValue);
    memo[sfMemoType.jsonName]   = strHex(memoType);
    memo[sfMemoFormat.jsonName] = strHex(memoFormat);
    memo[sfMemoData.jsonName]   = memoDataHex;

    Json::Value wrap(Json::objectValue);
    wrap[sfMemo.jsonName] = memo;

    Json::Value memos(Json::arrayValue);
    memos.append(wrap);
    jt.jv[sfMemos.jsonName] = memos;
}

// Attach memo for deposit: MemoType="zkp", MemoFormat="cm-v1"
// MemoData = hex(cm)
static void
attachZkpMemoDeposit(test::jtx::JTx& jt, uint256 const& cm)
{
    Json::Value memo(Json::objectValue);
    memo[sfMemoType.jsonName]   = strHex(std::string_view("zkp"));
    memo[sfMemoFormat.jsonName] = strHex(std::string_view("cm-v1"));
    memo[sfMemoData.jsonName]   = hex256(cm);

    Json::Value wrap(Json::objectValue);
    wrap[sfMemo.jsonName] = memo;

    Json::Value memos(Json::arrayValue);
    memos.append(wrap);

    jt.jv[sfMemos.jsonName] = memos;
}

// Attach memo for spend: MemoType="zkp", MemoFormat="cmnf-v1"
// MemoData = hex(cm_old)||hex(nf)
static void
attachZkpMemoSpend(test::jtx::JTx& jt, uint256 const& cmOld, uint256 const& nf)
{
    Json::Value memo(Json::objectValue);
    memo[sfMemoType.jsonName]   = strHex(std::string_view("zkp"));
    memo[sfMemoFormat.jsonName] = strHex(std::string_view("cmnf-v1"));
    memo[sfMemoData.jsonName]   = hex256(cmOld) + hex256(nf);

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
        return item.getFieldObject(sfMemo);

    return item;
}

// Journal for deposit:
// mode(1) || cm(32) => len = 33
static std::optional<uint256>
parseJournalDepositCm(Risc0Bytes const& journal)
{
    if (!journal.ptr || journal.len != 33)
        return std::nullopt;

    auto const* p = static_cast<std::uint8_t const*>(journal.ptr);
    if (p[0] != kModeDeposit)
        return std::nullopt;

    uint256 cm;
    std::memcpy(cm.begin(), p + 1, 32);
    return cm;
}

// Journal for spend:
// mode(1) || cm_old(32) || nf(32) => len = 65
static std::optional<std::pair<uint256, uint256>>
parseJournalSpendCmNf(Risc0Bytes const& journal)
{
    if (!journal.ptr || journal.len != 65)
        return std::nullopt;

    auto const* p = static_cast<std::uint8_t const*>(journal.ptr);
    if (p[0] != kModeSpend)
        return std::nullopt;

    uint256 cmOld, nf;
    std::memcpy(cmOld.begin(), p + 1, 32);
    std::memcpy(nf.begin(), p + 33, 32);

    return std::make_pair(cmOld, nf);
}

// get current account sequence number
// static std::uint32_t
// currentAccountSequence(test::jtx::Env& env, test::jtx::Account const& acct)
// {
//     auto const sle = env.le(keylet::account(acct.id()));
//     if (!sle)
//         return 0;
//     return sle->getFieldU32(sfSequence);
// }

}  // namespace test
}  // namespace ripple