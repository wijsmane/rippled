#ifndef XRPL_ZKP_NOTE_H_INCLUDED
#define XRPL_ZKP_NOTE_H_INCLUDED

#include <xrpl/basics/base_uint.h>     
#include <xrpl/basics/Blob.h>          
#include <xrpl/basics/random.h>        
#include <xrpl/protocol/AccountID.h>   
#include <xrpl/protocol/STAmount.h>          
#include <xrpl/protocol/Serializer.h>  
#include <xrpl/protocol/digest.h>     

#include <vector>
#include <utility>

namespace ripple {
namespace zkp {

    //note to hold private data, based on libsnark Note.h
    struct ZkNote
    {
        uint64_t  amount;
        uint256   rho; // uniqueness randomizer (no replay)
        uint256   r;  // commitment randomness
        uint256   payingKey; //recipient key so they can receive without revealing who they are

        ZkNote() = default;

        ZkNote(
            uint64_t const& amt, uint256 const& rho_, uint256 const& r_,  uint256 const& key_)
            : amount(amt), rho(rho_), r(r_), payingKey(key_)
        {
        }
    };

    //  commitment = sha512Half( 0x01 || amount_be(8) || rho(32) || r(32) || payingKey(32) )
    // 0x01 flag to distinguish from nullifiers
    inline uint256
    computeCommitment(ZkNote const& note)
    {
        Blob buf;
        buf.reserve(1 + 8 + 32 + 32 + 32);

        buf.push_back(0x01);
        append_u64_be(buf, note.amount);
        append_u256(buf, note.rho);
        append_u256(buf, note.r);
        append_u256(buf, note.payingKey);

        return zkHash(buf);
    }

    
    //  nullifier = sha512Half( 0x02 || spendKey(32) || rho(32) )
    inline uint256
    computeNullifier(uint256 const& spendKey, ZkNote const& note)
    {
        Blob buf;
        buf.reserve(1 + 32 + 32);

        buf.push_back(0x02);
        append_u256(buf, spendKey);
        append_u256(buf, note.rho);

        return zkHash(buf);
    }

    // HELPERS for serialising

    // takes a 64 bit integer and appends it to the blob (be = big endia = most significant byte first)
    inline void
    append_u64_be(Blob& out, std::uint64_t v)
    {
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }

    // takes uint256 and appends the bytes it represents to the blob
    inline void
    append_u256(Blob& out, uint256 const& x)
    {
        out.insert(out.end(), x.begin(), x.end());
    }

    // XRPL hash, SHA-512 then take first 32 bytes
    inline uint256
    zkHash(Blob const& data)
    {
        return sha512Half(makeSlice(data));
    }

}
}

#endif