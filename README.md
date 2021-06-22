# PAPR
A cryptographic scheme that allows for conditionally anonymous credentials, with the added benefit of public tamperproof logs of EVERY previous revocations.

## Installation
You are required to have Python3.9 and openSSL installed.

### without virtualenv 
```
pip3 install --user -r requirements.txt
```

### with virtualenv
```
pip3 install --user pipenv
pipenv install --dev  
```

## How to run
Not using virtualenv:
```
$ pytest
```

Using virtualenv:
```
$ pipenv run pytest
```


## Using devcontainer:
Install VS Code plugin: 
```
ms-vscode-remote.remote-containers
```

Click the two meeting arrows down left. Select build container or open in container.
Wait for the container to build and start.

## Setup bitcoin-testnet-box (NOTE: not needed for most tests):
Note this will install bitcoin-cli and bitcoind in user folder. Therefore it is recommended to use docker instead.

Make sure you have pulled the lastest git submodules:
```
git submodule update --init --recursive
```

Go into bitcoin-testnet-box. RECOMMENDED IN DOCKER.

```
cd bitcoin-testnet-box
./setup.sh
```

The next time you run it, instead use 
```
./start.sh
```

To make sure all users have bitcoins. Run the script:
```
./simulation/give_out_money.sh
```

# notes
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
Currently our implementation provides no support for blockchain based lists on the PAPR-level. Blockchain support is introduced first in PAPR-money. 

### Credential issuance
We chose to generate the cred in the beginning of the credential issuance procedure,
as to be able to link the user's incoming input to the issuer by its credential. 
The credential is not accepted as valid until the whole credential issuance procedure has been successfully executed.

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