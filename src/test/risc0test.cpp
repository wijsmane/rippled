#include <xrpl/beast/unit_test.h>
#include <risc0-ffi.h>  

#include <cstddef>
#include <cstdint>

namespace ripple {

class Risc0_test : public beast::unit_test::suite
{
public:
    void
    testProveRandomBytes()
    {
        unsigned char const data[] = {1,2,3,4,5};

        int const rc = risc0_prove_tx(data, sizeof(data));

        BEAST_EXPECT(rc == 0);
    }

    void
    run() override
    {
        testProveRandomBytes();
    }
};

BEAST_DEFINE_TESTSUITE(Risc0, protocol, ripple);

} // namespace ripple
