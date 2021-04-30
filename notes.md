# notes

## TODO
[x] ask about whether the elgamal-encryption for some reason has to be encrypted
with the previously used secret key, i.e. γ=l^d, and then use d again so as to create
γ^d
[x] make the issuance procedure take a Bn instead of bytes message
[x] implement ecdsa
[x] make sure the signature of pub_id is checkable by y_sign
[x] make ecdsa use hash that can hash any object 
[x] make parent_list that all others inherit from
[ ] fix test files
[ ] investigate if to remove z from return values of blind_show. 
    It is only there for eq_id. Not even sure it is supposed to use that z tho
[ ] Data distribution: Save custodian_list in relation to user (alternatively save parameters needed to recreate)
[ ] Data distribution: Save issuer random value in relation on user (can be discarded later if custodian_list is saved)
[ ] Make sure issuer knows who it receives revoke responses from 
[x] Bootstrap
[x] Same custodian can be selected twice
[x] You can select yourself as custodian (in bootstrap at least)
[ ] rename group_generator to h
[ ] Bootstrap scale exponentially. See if this can be fixed
[ ] anon auth takes t_id as argument -- even though the user could hold this value in self
[ ] investigate how to best use case sensitivity
[ ] Use self hosted bitcoin testnet if possible, otherwise investigate if regtest can be used instead
[ ] Implement more tests for customer with issuer
---
from root:
```
$ python -m grpc_tools.protoc -Iproto --python_out=papr --grpc_python_out=papr proto/papr.proto
```

issuer.setup(3,5)
print(crs)
print(i_pk)
print(self.sys_list.read())
True 115792089237316195423570985008687907852837564279074904382605163141518161494337,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,03dd5ee651b2ec33c98b1a3cf160574c9642be2b282bfef3f757ad860f6ba5982a,4,3,0251a310e10c109969a6844187cd5f5c6aa23e09bf1c6d50bb8e73cf76d8118153
True 0225cca713966d5023014a80a1d940089163b8a82ddc2004fc7bc13866e549f5d5,0204a7b9f5d02718b3e9ec9594df33d18fe8b83091247c6704321afac27a9301be
sys_list:  ['115792089237316195423570985008687907852837564279074904382605163141518161494337,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,03dd5ee651b2ec33c98b1a3cf160574c9642be2b282bfef3f757ad860f6ba5982a,4,3,0251a310e10c109969a6844187cd5f5c6aa23e09bf1c6d50bb8e73cf76d8118153', '0225cca713966d5023014a80a1d940089163b8a82ddc2004fc7bc13866e549f5d5,0204a7b9f5d02718b3e9ec9594df33d18fe8b83091247c6704321afac27a9301be']
((EcGroup(714), 115792089237316195423570985008687907852837564279074904382605163141518161494337, EcPt(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798), EcPt(03dd5ee651b2ec33c98b1a3cf160574c9642be2b282bfef3f757ad860f6ba5982a)), (EcPt(0225cca713966d5023014a80a1d940089163b8a82ddc2004fc7bc13866e549f5d5), EcPt(0204a7b9f5d02718b3e9ec9594df33d18fe8b83091247c6704321afac27a9301be)), {'X1': EcPt(0350742ddbec1edcb27c0f7ac622e11dbf4d6333c350dd8e79c392a7af80ed1567), 'Cx0': EcPt(0251a310e10c109969a6844187cd5f5c6aa23e09bf1c6d50bb8e73cf76d8118153)}, <papr.ledger.Ledger object at 0x7fd3666dfb50>, <papr.ledger.Ledger object at 0x7fd3666dfc40>, <papr.ledger.Ledger object at 0x7fd3666dfca0>, <papr.ledger.Ledger object at 0x7fd3666dffd0>)

## how to bitcoin
pip install bit
somehow install libsecp256k1 with your package manager
pip install https://download.electrum.org/4.0.9/Electrum-4.0.9.tar.gz

### testnet
https://armedia.com/blog/bitcoin-testnet-beginners-guide/

### get the coins
https://testnet-faucet.mempool.co/


## notes on implementation

### Blockchain
Currently our implementation provides no support for blockchain based lists on the PAPR-level. Blockchain support is introduced first in PAPR-money 

### Credential issuance
We chose to generate the cred in the beginning of the credential issuance procedure,
as to be able to link the user's incoming comms to the issuer by its credential. 
The credential is of course not accepted as valid until the whole credential issuance procedure has been successfully executed.

### List entries
#### sys_list
[crs, i_pk] where crs and i_pk are strings
#### user_list
(id, pub_id) where pub_id is EcPt and id is a string
#### cred_list
pub_cred = (y_e, y_s) = (y_encr, y_sign)
#### rev_list
(pub_cred, self.rev_data[pub_cred]) where rev_data[pub_cred] = (escrow_shares, custodians_encr_public_key) where escrow_shares = [s_e] and custodian_encr_pub_key = [pub_cred[0]] 
dict.items()


## Command to verify a transaction
bitcoin-cli -rpcport=19001 -rpcpassword=123 -rpcuser=admin1 -named gettransaction txid=581b61ff1bcfa05e6812d7b0170b486292958dfc4445301da3db6a8482e522cc