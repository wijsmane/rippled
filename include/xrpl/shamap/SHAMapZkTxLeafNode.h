#ifndef XRPL_SHAMAP_SHAMAPZKTXLEAFNODE_H_INCLUDED
#define XRPL_SHAMAP_SHAMAPZKTXLEAFNODE_H_INCLUDED

#include <xrpl/basics/CountedObject.h>
#include <xrpl/protocol/HashPrefix.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/shamap/SHAMapItem.h>
#include <xrpl/shamap/SHAMapLeafNode.h>

namespace ripple {

/** seperate leaf node for zk transaction
    Mostly the same except for getType and serialiseForWire
*/
class SHAMapZkTxLeafNode final : public SHAMapLeafNode,
                                 public CountedObject<SHAMapZkTxLeafNode>
{
public:
    SHAMapZkTxLeafNode(
        boost::intrusive_ptr<SHAMapItem const> item,
        std::uint32_t cowid)
        : SHAMapLeafNode(std::move(item), cowid)
    {
        updateHash();
    }

    SHAMapZkTxLeafNode(
        boost::intrusive_ptr<SHAMapItem const> item,
        std::uint32_t cowid,
        SHAMapHash const& hash)
        : SHAMapLeafNode(std::move(item), cowid, hash)
    {
    }

    intr_ptr::SharedPtr<SHAMapTreeNode>
    clone(std::uint32_t cowid) const final override
    {
        return intr_ptr::make_shared<SHAMapZkTxLeafNode>(item_, cowid, hash_);
    }

    SHAMapNodeType
    getType() const final override
    {
        return SHAMapNodeType::tnZK_TRANSACTION_NM;
    }

    void
    updateHash() final override
    {
        hash_ = 
            SHAMapHash{sha512Half(HashPrefix::transactionID, item_->slice())};
    }

    void
    serializeForWire(Serializer& s) const final override
    {
        // serialized ZkTxPayload
        s.addRaw(item_->slice());
        // different type for wire protocol so that others know it is zk tx
        s.add8(wireTypeZkTransaction);
    }

    void
    serializeWithPrefix(Serializer& s) const final override
    {
        s.add32(HashPrefix::transactionID);
        s.addRaw(item_->slice());
    }
};

}  // namespace ripple

#endif