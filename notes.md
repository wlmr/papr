# notes

## TODO
[x] ask about whether the engamal-encryption for some reason has to be encrypted
with the previously used secret key, i.e. γ=l^d, and then use d again so as to create
γ^d
[x] make the issuance procedure take a Bn instead of bytes message
[x] implement ecdsa
[x] make sure the signature of pub_id is checkable by y_sign
[x] make ecdsa use hash that can hash any object 
[x] make parent_list that all others inherit from
[ ] fix testfiles
[ ] investigate if to remove z from return values of blind_show. 
    It is only there for eq_id. Not even sure it is supposed to use that z tho
[ ] Data distrubution: Save custodian_list in relation to user (alternativly save parameters needed to recreate)
[ ] Data distrubution: Save issuer random value in relation on user (can be disgarded later if custodian_list is saved)
[ ] Make sure issuer knows who it recieves revoke responses from 
[x] Bootstrap
[ ] Same custodian can be selected twice
[ ] You can select yourself as custodian (in bootstrap at least)
[ ] rename group_generator to h
---
from root:
```
$ python -m grpc_tools.protoc -Iproto --python_out=papr --grpc_python_out=papr proto/papr.proto
```

issuer.setup(3,5)
print(crs)
print(i_pk)
print(self.sys_list.read())
((EcGroup(714), 115792089237316195423570985008687907852837564279074904382605163141518161494337, EcPt(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798), EcPt(03dd5ee651b2ec33c98b1a3cf160574c9642be2b282bfef3f757ad860f6ba5982a)), (EcPt(0280761ca3d4540ea67523ce02ff158526e8a0b400e3b62080ae07610549c28e4d), EcPt(023277f65b8ddfd3672c2cf49177f3c18581d00aae1529d67dbe8100e301467783)), {'X1': EcPt(03d63d1b98fb19d4e3e677e5dbddc976e392405e5052d76e0f77b560a7b6ce0176), 'Cx0': EcPt(03d2100deb2733cf34c886cd295d18d29e160e30d7b5a7d9a4e3c35484beaf1650)}, <papr.ledger.Ledger object at 0x7f72e0b915b0>, <papr.ledger.Ledger object at 0x7f72e0b91730>, <papr.ledger.Ledger
object at 0x7f72e0b916d0>, <papr.ledger.Ledger object at 0x7f72e0b91b50>)


## how to bitcoin
pip install bit
somehow install libsecp256k1 with your package manager
pip install https://download.electrum.org/4.0.9/Electrum-4.0.9.tar.gz

### testnet
https://armedia.com/blog/bitcoin-testnet-beginners-guide/

### get the coins
https://testnet-faucet.mempool.co/


## notes on implementation
### Credential issuance
We chose to generate the cred in the beginning of the credential issuance procedure,
as to be able to link the user's incoming comms to the issuer by its credential. 
The credential is ofcourse not accepted as valid until the whole credential issuance procedure has been sucessfully executed.

