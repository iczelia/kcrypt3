from z3 import *
r = [[BitVec(f'r_{i}_{j}', 32) for j in range(16)] for i in range(16)]
def initialize_sbox():
    sbox = [0] * 256
    p, q = 1, 1
    while True:
        p = p ^ (p << 1) ^ (0x1B if (p & 0x80) else 0)
        p &= 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q ^= 0x09 if (q & 0x80) else 0
        q &= 0xFF
        xformed = ((q << 1) | (q >> (8 - 1))) ^ ((q << 2) | (q >> (8 - 2))) ^ \
                  ((q << 3) | (q >> (8 - 3))) ^ ((q << 4) | (q >> (8 - 4)))
        xformed &= 0xFF
        sbox[p] = q ^ xformed ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox
sboxvec = initialize_sbox()
sbox = [BitVecVal(sboxvec[i], 32) for i in range(256)]
def symbolic_mtprod(r, sbox):
    temp = [[BitVec(f'temp_{i}_{j}', 32) for j in range(16)] for i in range(16)]
    for i in range(16):
        for j in range(16):
            temp[i][j] = Sum([r[i][k] * sbox[k * 16 + j] for k in range(16)])
    return temp
def trans16(r):
    return [[r[j][i] for j in range(16)] for i in range(16)]
def symbolic_rotl16(row, d):
    return [row[(i + d) % 16] for i in range(16)]
sbox_initialized = sbox
temp1 = symbolic_mtprod(r, sbox_initialized)
rotated = [symbolic_rotl16(row, i) for i, row in enumerate(temp1)]
temp2 = symbolic_mtprod(trans16(rotated), sbox_initialized)
result = [((temp2[i][i] >> 16) ^ (temp2[i][i])) & 0xFF for i in range(16)]
simplified_results = [simplify(result[i]) for i in range(16)]
print(simplified_results)
