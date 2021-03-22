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
[ ] Bootstrap
<<<<<<< HEAD
[ ] Same custodian can be selected twice
[ ] You can select yourself as custodian (in bootstrap at least)
=======
[ ] rename group_generator to h
>>>>>>> 950589ad67b4162f6b57107a37308ac1fe36d33b
---
from root:
```
$ python -m grpc_tools.protoc -Iproto --python_out=papr --grpc_python_out=papr proto/papr.proto
```
