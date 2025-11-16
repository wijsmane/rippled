## first draft of architecture

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

Can use most things from SNARK architecture
- Separate Merkle tree for storing note commitments in leaf nodes, storing only the root of this tree on ledger
    -> do this to keep node storage requirements low
- Create new transaction types
- ZKProver and MerkleCircuit - change to use LibSTARK functionality
- ZKDeposit and ZKWithdraw
- shielded pool to track aggregate counts
- no trusted setup -> do not need keys
