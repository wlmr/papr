
import os
from bit import wif_to_key


for directory, subdirectories, files in os.walk("../data"):
    for file in files:
        if file.endswith("-key"):
            path1 = os.path.join(directory, file)
            try:
                wif_file = open(path1, "r")
                wif = wif_file.read()
                key = wif_to_key(wif)
                print(key.address)
                wif_file.close()
                del wif
                del key
                del wif_file
            except FileNotFoundError:
                pass
