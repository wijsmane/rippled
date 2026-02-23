#include <test/jtx.h>

#include <xrpl/basics/strHex.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/protocol/SField.h>

#include <random>
#include <cstring>

namespace ripple {
namespace test {

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

static std::string
hex256(uint256 const& u)
{
    return strHex(u.begin(), u.end());
}

class ZkpMemos_test : public beast::unit_test::suite
{
public:
    void
    testMemoCarriesCmNf()
    {
        testcase("zkp memo carries cm||nf");

        using namespace test::jtx;

        Account alice{"alice"};
        Env env(*this);
        env.fund(XRP(10000), alice);
        env.close();

        uint256 const cm = randomUint256();
        uint256 const nf = randomUint256();

        JTx jt = noop(alice);

        // jtx builds correct structure and then replace it with cm and nf
        memo const m{"placeholder", "cmnf-v1", "zkp"};
        m(env, jt);

        jt.jv[sfMemos.jsonName][0u][sfMemo.jsonName][sfMemoData.jsonName] =
            hex256(cm) + hex256(nf);

        //submit
        env(jt);
        env.close();

        //read the tx
        auto tx = env.tx();
        BEAST_EXPECT(tx);

        if (!tx)
            return;

        BEAST_EXPECT(tx->isFieldPresent(sfMemos));

        auto const& memosArr = tx->getFieldArray(sfMemos);
        BEAST_EXPECT(memosArr.size() == 1);

        if (memosArr.size() != 1)
            return;

        auto const& item = memosArr[0];

        // retrieve memo
        STObject const& memoObj = item.isFieldPresent(sfMemo)
            ? item.getFieldObject(sfMemo)
            : item;

        BEAST_EXPECT(memoObj.isFieldPresent(sfMemoType));
        BEAST_EXPECT(memoObj.isFieldPresent(sfMemoFormat));
        BEAST_EXPECT(memoObj.isFieldPresent(sfMemoData));

        // get memo bytes
        auto const typeBlob = memoObj.getFieldVL(sfMemoType);
        auto const fmtBlob  = memoObj.getFieldVL(sfMemoFormat);
        auto const dataBlob = memoObj.getFieldVL(sfMemoData);

        // get expected bytes for comparison
        auto const expType = strUnHex(strHex(std::string_view("zkp"))).value_or(Blob{});
        auto const expFmt  = strUnHex(strHex(std::string_view("cmnf-v1"))).value_or(Blob{});
        auto const expData = strUnHex(hex256(cm) + hex256(nf)).value_or(Blob{});

        //compare bytes
        BEAST_EXPECT(typeBlob == expType);
        BEAST_EXPECT(fmtBlob  == expFmt);
        BEAST_EXPECT(dataBlob == expData);

        //size check to be sure
        BEAST_EXPECT(dataBlob.size() == 64);

    }

    void
    run() override
    {
        testMemoCarriesCmNf();
    }
};

BEAST_DEFINE_TESTSUITE(ZkpMemos, zkp, ripple);

} // namespace test
} // namespace ripple
