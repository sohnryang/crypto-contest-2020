# 3번 블록 암호 문제 분석과 풀이

Jupyter notebook을 C++으로 쓰는데는 무리가 있어 이렇게 대체한다.

## 암호화 방식에 대한 고찰

문제에 나와 있는 암호화 과정을 보자. (의사코드를 파이썬으로 바꾸었다.)

```python
import numpy as np

def encrypt(plaintext, init_vector):
		P = plaintext.split_blocks()
		G = init_vector
		C = [] # ciphertext
		for i in range(len(P)):
    		C.append(aria128_encrypt(np.logical_xor(P[i], G)))
		    G = np.logical_xor(P)
    return C
```

이러한 암호화 방식을 [PCBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC))라고 부른다. 여기서 중요한 점은 PCBC 암호화의 경우, 인접한 두 암호문 블록의 순서가 바뀌어도, 암호화 결과에 영향을 주지 않는다는 점이다.