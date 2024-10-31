# kcrypt2
a proof-of-concept for cryptographic systems based on the intractable problem of polynomial reconstruction (related to NP-hard linear code decoding problem). the algorithm is described in https://palaiologos.rocks/posts/rolling-my-own-crypto/. most of the code handles edge cases that could cause information leakage from the primitive. the author hopes that the internal RNG state can not be recovered due to how much data is being tossed out and how small the primitive block is.
list of related concepts/topics:
- https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction
- https://en.wikipedia.org/wiki/Finite_field
- https://en.wikipedia.org/wiki/McEliece_cryptosystem
