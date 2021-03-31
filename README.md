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