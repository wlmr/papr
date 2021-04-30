# PAPR
---

Cryptographic scheme that allows for conditionally anonymous credentials, with the added benefit of public tamperproof logs of all previous revocations.



## Installation
---
Not using virtualenv: 
```
pip3 install --user -r requirements.txt
```

It can be run inside a python virtualenv. The easiest way is to run:
```
pip3 install --user pipenv
pipenv install --dev  
```

## How to run
---

Not using virtualenv:
```
$ pytest
```

Using virtualenv:
```
pipenv run pytest
```


## Using devcontainer:
Install VS Code plugin: 
```
ms-vscode-remote.remote-containers
```

Click the two meeting arrows down left. Select build container or open in container.
Wait for the container to build and start.

## Setup bitcoin-testnet-box:
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