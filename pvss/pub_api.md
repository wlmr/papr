# PVSS api

## Secret distribution
```
pvss.distribute_secret(pub_keys, secret, p, k, n, eliptic_curve_group): -> 
    (enc_shares, commitments, proof, random_generator)
```

## Verify encrypted shares
```
pvss.verify_encrypted_shares(self, encrypted_shares, commitments, pub_keys, proof, h): ->
    boolean
```

## Decrypt
```
pvss_participant = PVSS.PVSS_participant(params) 
pvss_participant.participant.generate_key_pair(): -> 
    public_key

pvss_participant.participant_decrypt_and_prove(encrypted_share): ->
    (decrypted_share, proof_of_decryption)
```
## Verify decryption
```
pvss.verify_decryption_proof(proof_of_decryption, decrypted_share, encrypted_share, public_key): ->
    Boolean
```

## Reconstruct
```
pvss.reconstruct(decrypted_list, index_list): ->
    secret * G
```      

