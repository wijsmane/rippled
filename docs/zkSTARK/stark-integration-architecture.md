# Second Draft of Architecture

LibSTARK proof generation overview
1. BAIR (Boolean Algabraic Intermediate Representation) instance defines the generic constraints (create 1 instance for each transaction type)
    - constructor takes vectorsLen (number of variables per step in the computation), and domainSizeIndicator (number of steps in the computation)
    - instance includes assignment constraints, permutation constraints, and boundary constraints
2. BAIR witness sets the inputs/outputs for the transaction (create new witness for each individual transaction)
    - will include the transaction data, note commitments, nullifiers, merkle paths
    - represents computational trace in a 2D array
3. executeProtocol() in protocol.cpp 
    - converts BAIR to ACSP (Algebraic Constraint Satisfaction Problem) to get low-level polynomial constraints suited to STARKs
    - generates/verifies STARK proofs via ALI (Algebraic Linking Interactive Oracle Proof) prover/verifier

Goal = integrate with XRPL's existing merkle tree
- identify what is missing in terms of ZKPs by comparing with libsnark approach and fill in the missing logic
- no trusted setup -> do not need keys

## Example Deposit Transaction
Prover
1. Prepare transaction
    - create a note with secret transaction data including sourceAccount, destAccount, amount, fee, sequence number
    - get note commitment by hashing this, using a secret random value

    ** need to write logic, note.h from SNARK?

2. Construct BAIR instance for a generic payment transaction (should only need to do this once for each transaction type)
    
    BairInstance(

		const size_t vectorsLen, // number of variables per step

		const short domainSizeIndicator, // number of steps

		constraintsPtr_t&& constraints_assignment, // updates of balances through the steps

		constraintsPtr_t&& constraints_permutation, // ensure repeated values are the same across steps

		const boundaryConstraints_t& boundaryConstraints, // can use to fix the previous balances

        const std::vector<Algebra::FieldElement>& paddingPi // optional, helps permutation constraints link variables correctly

    )

3. Construct BAIR witness for the transaction

    BairWitness(

		assignment_ptr&& assignment, // holds the real transaction data as a sequence of vectors of FieldElements (one FE per variable, domainSizeIndicator number of vectors)

		permutation_ptr&& permutation // enforce consistency across steps

    )

    assignment should include the note secrets and randomness used for the commitment (to ensure it was computed correctly)

4. Generate proof

    executeProtocol(instance, witness, security parameter)
    - this runs an interaction between the prover and verifier internally and then returns a bool for success/failure -> no function that is just "generateProof" to return a proof

    Maybe extract proof by recording the messages that are sent to the verifier?

    - generate prover

        must first convert BAIR witness to ACSP:

        AcspWitness = CBairToAcsp::reduceWitness(BairInstance, BairWitness)

        prover = libstark::Protocols::Ali::Prover::prover_t(BairInstance, AcspWitness, Biased_prover)
        -> Biased_prover is a provided RS_proverFactory which specifies how to create the low degree proof sub-provers

    - would have to generate verifier and the run the interaction to simulate and then save the messages

        libstark::Protocols::Ali::Verifier::verifier_t(bairInstance, RSVerifierFactory, securityParameter)

        vector<message> allMessages;.

        while(!verifier.doneInteracting) {

            msg = prover.sendMessage();

            allMessages.push_back(msg);

            verifier.receiveMessage(msg);

            verifierMsg = verifier.sendMessage();

            prover.receiveMessage(verifierMsg);

        }

        so the proof would be allMessages

5. Store proof and commitmnet in a transaction
    - must serialize proof -> need to write a function for this? put into STBlob (like SNARK)?

    - create new transaction entry including new fields for the serialised proof and for the note commitment (does not include private data)

        ripple::STTx tx(ripple::ttPAYMENT, ripple::Ledger::getCurrentLedgerIndex())

        **should we include entire proof in the transaction? will be a lot to store in the shamap

    - sign transaction with Alice's Ripple keys

        tx.sign(alicePublic, alicePrivate)

        this adds the signature to the transaction and calculates the transaction ID (stored as tid_)

    - serialize full transaction

        use some function from Protocol::Serializer?

    - send to verifier

*Proof only proves that the transaction satisfies constraints, doesn't prove inclusion in ledger

Verifier

1. Deserialize transaction to get data
2. Verify signature

    Expected<void, std::string> result = deserializedTransaction.checkSign(RequireFullyCanonicalSig::yes, rules);

    (returns void if verify success, a string if failure)

    (need to get rules)

3. Get the BAIR instance, commitment, and proof and run verifier

    - would need to again run the interaction between prover and verifier

4. If signature and proof were both valid, add to ledger

    - add to SHAMap

        SHAMap::addItem(SHAMapNodeType type, boost::intrusive_ptr<SHAMapItem const> new SHAMapItem(getTransactionID(), serializedTransaction));

    - SHAMap handles inclusion, will automatically recompute new root
