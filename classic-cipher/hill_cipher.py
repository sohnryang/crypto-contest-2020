"""
hill_cipher.py

Solution to problem #3.
"""

import itertools
from collections import Counter
from pprint import pprint

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
    d = np.zeros((m, blocksize))
    for t in range(blocksize):
        for i in range(m):
            d[i][t] = sum(blocks[i][:t + 1]) % 26

    inv_K = np.zeros((blocksize, blocksize))
    I = np.full((blocksize,), -np.inf)
    p = [0] * m
    iml = maximum_likelyhood(p)
    for x in itertools.product(range(26), repeat=blocksize):
        if sum(x) == 0:
            continue
        print('trying vector: ', end='')
        pprint(x)
        vec = np.array(x)
        t = np.argmax(vec != 0)
        for i in range(m):
            iml = iml - np.log2(monogram_prob[p[i]]) / m
            p[i] = int((p[i] + d[i][t]) % 26)
            iml = iml + np.log2(monogram_prob[p[i]]) / m
        if sum(vec % 2) != 0 or sum(vec % 13) != 0:
            transposed = inv_K.transpose()
            for i in range(len(transposed)):
                if maximum_likelyhood(transposed[i]) < iml:
                    transposed[i] = vec
                    I[i] = iml

    return inv_K

def text_to_numlist(text):
    result = []
    for c in text:
        result.append(ord(c) - ord('A'))
    return result

with open('encrypted.txt') as f:
    encrypted = f.read().strip()
    print(encrypted)

key = crack_hill(text_to_numlist(encrypted), 5)
pprint(key)
