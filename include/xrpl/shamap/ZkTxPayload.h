#ifndef XRPL_PROTOCOL_ZKTXPAYLOAD_H_INCLUDED
#define XRPL_PROTOCOL_ZKTXPAYLOAD_H_INCLUDED

#include <xrpl/basics/base_uint.h>      
#include <xrpl/protocol/AccountID.h>    
#include <xrpl/protocol/STAmount.h>     
#include <xrpl/protocol/Serializer.h>   
#include <xrpl/basics/Blob.h>           

namespace ripple {

// this file is to store the public ZK transaction data in the shamap after verification
struct ZkTxPayload
{
    // ZK-specific
    uint256       nullifier;     
    uint256       commitment;    // commitment used in the zk circuit
    
    // XRPL native , need to look at serialisation info? https://github.com/Xtinc-T/Crypography-Basics/blob/release/02.%20Protocol/4.%20Protocl_Serialization.md

    std::uint32_t ledgerSeq;     // the index in the ledger that the record is at
    uint256       txHash;        // txID
    uint256       merkleRoot;    // would this be the root before this tx is inserted, or after?
    //acount id of sender/recipient?
    //amount?

    void
    add(Serializer& s) const
    {
        s.add256(nullifier);
        s.add256(commitment);
        s.add32(ledgerSeq);
        s.add256(txHash);
        s.add256(merkleRoot);
    }

    Blob
    getBlob() const
    {
        Serializer s;
        add(s);
        return s.peekData();
    }
};

}  // namespace ripple

#endif