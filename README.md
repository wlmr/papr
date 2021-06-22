# PAPR
A cryptographic scheme, proposed by Joakim Brorsson and Paul Stankovski Wagner, that allows for conditionally anonymous credentials, with the added benefit of public tamperproof logs of EVERY previous revocations.

## Installation
You are required to have Python3.9 and openSSL installed. How to install the dependencies are covered below.

### Install and run (easy way)
1. Install Docker, Visual studio code and the following VS Code plugin: 
```
ms-vscode-remote.remote-containers
```

2. Open the project in VS code
3. Click the two meeting arrows in the bottom left corner. Select build container or Reopen in Container.
4. Wait for the container to build and start.
5. Open a terminal window inside VS code.
6. Once the container has started, run the following:
```
pytest
```

7. To run our simulations, run:
```
python3 simulations/<SIMULATION_NAME>
```
The results will be stored in the root of the project.


### Install and run (less easy way) 
This way requires root access.

Tested in docker container ubuntu:latest.
```
## Clone project
apt update && apt upgrade -y && apt install git -y
git clone https://github.com/wlmr/papr.git

## Install Python 3.9
apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev -y
wget https://www.python.org/ftp/python/3.9.1/Python-3.9.1.tgz
tar -xf Python-3.9.1.tgz
cd Python-3.9.1
./configure --enable-optimizations
make -j 4
make altinstall
cd ..

## Install dependencies
apt-get install python-dev -y
apt-get install libssl-dev libffi-dev -y
export PATH='~/.local/bin':$PATH

## Install Python dependencies
cd papr
PYTHONPATH='.'
/usr/local/bin/python3.9 -m pip install --upgrade pip
pip3.9 install --user -r requirements.txt

## Run pytest
python3.9 -m pytest
```
To run our simulations, run:
```
python3.9 simulations/<SIMULATION_NAME>
```
The results will be stored in the root of the project.

## Notes on bitcoin
### How to bitcoin
pip install bit
somehow install libsecp256k1 with your package manager
pip install https://download.electrum.org/4.0.9/Electrum-4.0.9.tar.gz

#### Testnet
https://armedia.com/blog/bitcoin-testnet-beginners-guide/

#### Get the coins
https://testnet-faucet.mempool.co/


## Notes on the code

### Blockchain
Currently our implementation provides no support for blockchain based lists on the PAPR-level. Blockchain support is introduced first in PAPR Money, albeit not fully functional at the moment. 

### Credential issuance
We chose to generate the credential in the beginning of the credential issuance procedure,
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
