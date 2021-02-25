# Notes


## how to structure amac
+ in "test function" "if __name__ == "__main__":"
1. declare message m
### setup system: 
1. params = setup() //setup key underlying algebraic mac-system
2. (d, gamma) = elgamal_keygen(params) //setup elgamal key-pair
3. (iparams, sk) = cred_keygen(params, n) //setup keyed-verification credential system

### issuance
1. user asks for credential (prepare_blind_obtain(gamma,m) -> E,obtainer_proof)
    1. generate elgamal keypair
    2. encrypt each attribute multiplied by g with the elgamal key with some random r
    3. sends the encryption E along with proof of knowledge of r and m to issuer
2. issuer checks the the proofs (blind_issue(E,pi_issuer_proof))
    1. chooses a random b and computes u = g^b
    2. rearanges E to E'_u' as described in the paper
    3. sends (u, E'_u') and proof of knowledge x's x_tilde, b and r back to the user
3. blind_obtain()

### show


## JOURNAL

20-02-23: have been doing proofs for the whole day. Will pick up at make_pi_issue tomorrow


