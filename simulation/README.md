# simulations

## Load Sim
Running this script will, after some time, have run all multiples of 10 up to 400, for n. This was neccessary to keep all the CPU cores running until n = 200, without some of the cores becoming unemployed and hence affecting the speed of the remaining cores. We have provided a (zsh script)[simulation/scripts/occurrence_checker.sh] that takes as argument the path to the output-file of load_sim.py. The script counts the number of occurrences for each n and tells you how many k's are missing for each. The script can be used to know when to kill the simulation. The script assumes you are running all multiples of ten for n and all multiples of 5 for k, while k is less than n.

## TO RUN
To execute the simulations we need the issuer to disable its registry persistence. Hence, you are required to comment out the following code in [the bank-class](../papr_money/bank.py)
```
        try:
            with open("data/bank-registry", "rb") as file:
                G = EcGroup(714)
                byte_dict = load(file)
                self.registry = {address: EcPt.from_binary(byte_string, G) for address, byte_string in byte_dict.items()}
        except (FileNotFoundError, EOFError):
            self.registry = {}

    def __del__(self):
        with open("data/bank-registry", "wb") as file:
            dump({address: pub_key.export() for address, pub_key in self.registry.items()}, file)
```