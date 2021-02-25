#!/usr/bin/env python3
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from dealer import PVSS
from hashlib import sha256


class DLEQ():

    def __init__(self, params):
        global G
        global g
        global p
        global G
        global h
        (Gq, p, g, G, h) = params
        

  


