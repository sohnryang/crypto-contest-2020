"""
hill_cipher.py

Solution to problem #3.
"""

import itertools
from collections import Counter
from pprint import pprint
from sys import argv

import numpy as np

monogram_prob = np.array([
    0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, # ABCDEFGH
    0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019, # IJKLMNOP
    0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, # QRSTUVWX
    0.020, 0.001                                            # YZ
])

def normalized_freq(text):
    counter = Counter(text)
    result = np.zeros((26,))
    for i in range(26):
        if i not in counter:
            result[i] = 0
            continue
        result[i] = counter[i]
    return result / len(text)

def maximum_likelyhood(text):
    return -sum(normalized_freq(text) * np.log2(monogram_prob))

def crack_hill(ciphertext, blocksize):
    assert len(ciphertext) % blocksize == 0

    blocks = np.array_split(ciphertext, len(ciphertext) // blocksize)
    m = len(blocks)
    d = np.zeros((m, blocksize)).astype(int)
    for t in range(blocksize):
        for i in range(m):
            d[i][t] = sum(blocks[i][:t + 1]) % 26

    pprint(d)

    inv_K = np.zeros(blocksize, blocksize).astype(int)
    I = np.full((blocksize,), -np.inf)
    p = [0] * m

    for x in itertools.product(range(26), repeat=blocksize):
        if sum(x) == 0:
            continue
        vec = np.array(x).astype(int)
        t = np.argmax(vec != 0)
        print('Current vector: ', end='')
        pprint(vec)
        for i in range(m):
            p[i] = int((p[i] + d[i][t]) % 26)
        print('Current p: ', end='')
        print(p)
        iml_x = maximum_likelyhood(p)
        iml_y = I.min()
        cand = I.argmin()
        mod_2_is_zero = vec % 2 == 0
        mod_13_is_zero = vec % 13 == 0
        if not np.all(np.logical_or(mod_2_is_zero, mod_13_is_zero)):
            if iml_y < iml_x:
                np.swapaxes(inv_K, 0, 1)
                inv_K[cand] = vec
                np.swapaxes(inv_K, 0, 1)
                I[cand] = iml_x
            print('Current matrix:')
            pprint(inv_K)
            print('Current I: ', end='')
            pprint(I)
        else:
            print('Skipped')

    return inv_K

def text_to_numlist(text):
    result = []
    for c in text:
        result.append(ord(c) - ord('A'))
    return result

assert len(argv) == 3
with open(argv[1]) as f:
    encrypted = f.read().strip()

numlist = text_to_numlist(encrypted)
print(numlist)
key = crack_hill(numlist, int(argv[2]))
pprint(key)
