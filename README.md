# kcrypt2
a proof-of-concept for cryptographic systems based on the intractable problem of polynomial reconstruction (related to NP-hard linear code decoding problem). the algorithm is described in https://palaiologos.rocks/posts/rolling-my-own-crypto/. most of the code handles edge cases that could cause information leakage from the primitive. the author hopes that the internal RNG state can not be recovered due to how much data is being tossed out and how small the primitive block is.
list of related concepts/topics:
- https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction
- https://en.wikipedia.org/wiki/Finite_field
- https://en.wikipedia.org/wiki/McEliece_cryptosystem

known vulnerabilities: key reuse attack

```
 0 [14:47] Desktop/workspace/kcrypt2@main % ./kcrypt2c -g key.kck
 0 [14:47] Desktop/workspace/kcrypt2@main % ./kcrypt2c -e key.kck stuff.txt stuff.enc
 0 [14:47] Desktop/workspace/kcrypt2@main % ./kcrypt2c -e key.kck stuff2.txt stuff2.enc
 0 [14:47] Desktop/workspace/kcrypt2@main % xxd stuff.enc
00000000: 36ed df7c 1238 7e58 c699 5795 e76f 2fdd  6..|.8~X..W..o/.
00000010: 36ac e258 5a5e 394b 6a3a 4eda 6e69 5381  6..XZ^9Kj:N.niS.
 0 [14:47] Desktop/workspace/kcrypt2@main % xxd stuff2.enc
00000000: 36ed df7c 1238 7e58 c699 5795 e76f 2fdd  6..|.8~X..W..o/.
00000010: fcfd 1eda 3f0f aefe 06f0 c77f c4b1 0873  ....?..........s
 0 [14:48] Desktop/workspace/kcrypt2@main % cat stuff.txt
This is message 1
 0 [14:48] Desktop/workspace/kcrypt2@main % cat stuff2.txt
This is message 2
```
