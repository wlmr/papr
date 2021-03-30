from bit import PrivateKeyTestnet

my_key = PrivateKeyTestnet()
print(my_key.address)
print(my_key.version)
print(my_key.to_wif())
