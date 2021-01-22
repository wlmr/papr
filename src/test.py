from charm.toolbox.integergroup import IntegerGroup
group1 = IntegerGroup()
group1.paramgen(1024)
g = group1.randomGen()
print(g)
print("hello")