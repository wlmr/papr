# Public api

distribute_secrets(selected_pub_keys, secret, params, k, n, h?): -> encrypted_shares, commitments, proof of shares being the same in commitment and enc.

verify_encrypted_shares(enc_shares, commitments, proof, h?) -> boolean

decrypt_share(encrypted_share, <internal priv key>) -> decrypted_share, proof_of_decryption

reconstruct_given_decrypted_shares(decrypted_shares) -> secret*

verify_decryption_proof(proof_of_decryption, decrypted_share) -> Boolean