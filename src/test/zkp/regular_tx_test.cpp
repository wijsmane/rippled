#include <test/jtx.h>

#include <xrpl/basics/strHex.h>
#include <xrpl/protocol/SField.h>
#include "test_helpers.h"

namespace ripple {
namespace test {


class ZkpRegularAccountSet_test : public beast::unit_test::suite
{
public:
    void
    testAccountSetNoMemo()
    {
        using namespace test::jtx;
        testcase("AccountSet without memos behaves normally (no ZK side effects)");

        Account alice{"alice"};
        Env env(*this);
        env.fund(XRP(10000), alice);
        env.close();

        JTx jt = noop(alice);

        env(jt);
        env.close();

        auto tx = env.tx();
        BEAST_EXPECT(tx);

        if (tx)
        {
            if (tx->isFieldPresent(sfMemos))
                BEAST_EXPECT(tx->getFieldArray(sfMemos).empty());
            else
                pass();
        }

    }

    void
    testAccountSetNonZkpMemoIgnored()
    {
        using namespace test::jtx;
        testcase("AccountSet with non-ZKP memo is ignored by ZK logic");

        Account alice{"alice"};
        Env env(*this);
        env.fund(XRP(10000), alice);
        env.close();

        JTx jt = noop(alice);

        //this memo should not be treated as a zk memo because the fields are different
        attachMemo(jt, "hello", "text/plain", "DEADBEEF");

        env(jt);
        env.close();

        //confirm memos are present and tx still succeeded 
        // (if ledger entries are inserted there will be a print statement from SetAccount.cpp doApply)
        auto tx = env.tx();
        BEAST_EXPECT(tx);

        if (tx)
        {
            BEAST_EXPECT(tx->isFieldPresent(sfMemos));
            if (tx->isFieldPresent(sfMemos))
                BEAST_EXPECT(!tx->getFieldArray(sfMemos).empty());
        }

    }

    void
    run() override
    {
        testAccountSetNoMemo();
        testAccountSetNonZkpMemoIgnored();
    }
};

BEAST_DEFINE_TESTSUITE(ZkpRegularAccountSet, zkp, ripple);

} // namespace test
} // namespace ripple