
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
// Prelude
#define Fi(n, a...)for(int i=0;i<n;i++){a;}
#define Fid(n, a...)for(int i=n-1;i>=0;i--){a;}
#define Fid1(n, a...)for(int i=n-1;i>0;i--){a;}
#define Fj(n, a...)for(int j=0;j<n;j++){a;}
#define XCH(k,x,y){k t=x;x=y;y=t;};
#define _(a...) {return({a;});}
#define S static
#define V void
typedef uint8_t u8;   typedef uint16_t u16;
typedef uint32_t u32; typedef uint64_t u64;
S u8 M[256][256], D[256], LOG[256], EXP[510];   S FILE * rng;
V init() {
  int b = 1;  rng = fopen("/dev/urandom", "r");
  Fi(255, LOG[b] = i;  EXP[i] = EXP[i + 255] = b;
          if ((b <<= 1) >= 256) b = (b - 256) ^ 0x1D)
  Fi(256, Fj(256, if (i && j) M[i][j] = EXP[LOG[i] + LOG[j]]))
  Fi(256, int d = LOG[1] - LOG[i]; D[i] = EXP[d < 0 ? d + 255 : d])}
int cleanup()_(fclose(rng))
typedef struct { u8 p[128], b[16]; u32 mt[624], mti; } key;  S FILE * rng;
S u32 mtn(key * k) {
  u32 y, mag01[2] = { 0, 0x9908b0df };
  if (k->mti >= 624) {
    Fi(227, y = (k->mt[i] & 0x80000000) | (k->mt[i + 1] & 0x7fffffff);
            k->mt[i] = k->mt[i + 397] ^ (y >> 1) ^ mag01[y & 1])
    Fi(396, y = (k->mt[i + 227] & 0x80000000) | (k->mt[i + 228] & 0x7fffffff);
            k->mt[i + 227] = k->mt[i] ^ (y >> 1) ^ mag01[y & 1])
    y = (k->mt[623] & 0x80000000) | (k->mt[0] & 0x7fffffff);
    k->mt[623] = k->mt[396] ^ (y >> 1) ^ mag01[y & 1]; k->mti = 0;
  }
  y = k->mt[k->mti++];         y ^= y >> 11;
  y ^= (y << 7) & 0x9d2c5680;  y ^= (y << 15) & 0xefc60000;
  return y ^ (y >> 18);}
// Key
key kc_keygen()_(key k; Fi(624, k.mt[i] = fgetc(rng)); k.mti = 0; k)
#define KEY_SHUF Fid1(128, int j = mtn(k)%(i+1); XCH(u8, k->p[i], k->p[j]))
S V kc_nextkey(key * k) {
  Fi(128, k->p[i] = i)  Fi(16, k->b[i] = 0) KEY_SHUF
  Fi(64, k->b[k->p[i] >> 3] |= 1 << (k->p[i] & 7)) KEY_SHUF}
// Polynomial
S V kc_lagrange72(u8 * x, u8 * y, u8 * c) {
  u8 li[72] = { 0 }; li[0] = 1;
  Fi(72, memset(li, 0, 72); li[0] = 1; Fj(72, 
    if (i == j) continue;
    u8 d = D[x[i] ^ x[j]];
    Fid1(72, li[i] = li[i - 1] ^ M[li[i]][x[j]])
    li[0] = M[li[0]][x[j]];
    Fi(72, li[i] = M[li[i]][d]))
  Fj(72, c[j] ^= M[li[j]][y[i]]))}
S V kc_lagrange64(key * k, u8 * x, u8 * y, u8 * c) {
  u8 aX[72], aY[72]; memcpy(aX, x, 64); memcpy(aY, y, 64);
  Fi(8, aX[64 + i] = 64 + i; aY[64 + i] = mtn(k) % 256)
  kc_lagrange72(aX, aY, c);}
S u8 kc_horner71(u8 * c, u8 x)_(u8 r=c[71];Fid(71,r=M[r][x]^c[i])r)
// Encrypt/decrypt
S V kc_block_encrypt(key * k, u8 in[64], u8 out[128]) {
  kc_nextkey(k); u8 id[64], tmp[128]; Fi(64, id[i] = i) u8 c[72] = { 0 };
  kc_lagrange64(k, id, in, c); Fi(128, tmp[i] = kc_horner71(c, 128 + i))
  Fi(128, if (k->b[i >> 3] & (1 << (i & 7))) tmp[i] = fgetc(rng))
  Fi(128, out[i] = tmp[k->p[i]])}
S V kc_block_decrypt(key * k, u8 in[128], u8 out[64]) {
  kc_nextkey(k);  u8 c[128], x[64], y[64], j = 0;
  { u8 ip[128]; Fi(128, ip[k->p[i]] = i) Fi(128, c[i] = in[ip[i]]) }
  Fi(128, if (!(k->b[i >> 3] & (1 << (i & 7)))) x[j] = 128 + i, y[j++] = c[i])
  memset(c, 0, 72);  kc_lagrange64(k, x, y, c); Fi(64, out[i] = kc_horner71(c, i))}
u64 kc_encrypt(key * k, u8 * in, u8 * out, u64 sz) {
  u8 * base = out;
  for(; sz > 64; in += 64, out += 128, sz -= 64) kc_block_encrypt(k, in, out);
  u8 tmp[64] = { 0xAA };  memcpy(tmp, in, sz); tmp[63] = sz;
  kc_block_encrypt(k, tmp, out);  return out - base + 128;}
u64 kc_decrypt(key * k, u8 * in, u8 * out, u64 sz) {
  u8 * base = out;
  for (; sz > 128; in += 128, out += 64, sz -= 128) kc_block_decrypt(k, in, out);
  if (sz != 128) return 0; u8 tmp[128];  kc_block_decrypt(k, in, tmp); sz = tmp[63];
  memcpy(out, tmp, sz);  memset(out + sz, 0, 64 - sz);  return out - base + sz;}
// Driver.
size_t file_size(FILE * f) { size_t sz; fseek(f, 0, SEEK_END); sz = ftell(f); rewind(f); return sz;}
void read_key(FILE * f, key * k) {
  k->mti = 0; fread(k->p, 1, 128, f); fread(k->b, 1, 16, f); fread(k->mt, 1, 624 * 4, f); fclose(f);}
#define FOPEN_CHK(f) if (!f) { perror("fopen"); exit(1); }
int main(int argc, char * argv[]) {
  init();
  if(!strcmp(argv[1], "e")) {
    FILE * plaintext = fopen(argv[2], "rb"); FOPEN_CHK(plaintext)
    FILE * key_input = fopen(argv[3], "rb"); FOPEN_CHK(key_input)
    FILE * ciphertext = fopen(argv[4], "wb"); FOPEN_CHK(ciphertext)
    size_t plaintext_size = file_size(plaintext);
    u8 * buf = malloc(plaintext_size);
    fread(buf, 1, plaintext_size, plaintext);
    fclose(plaintext);
    key k; read_key(key_input, &k);
    u8 * enc = malloc(plaintext_size * 2 + 128);
    u64 encsz = kc_encrypt(&k, buf, enc, plaintext_size);
    fwrite(enc, 1, encsz, ciphertext);
    fclose(ciphertext);
  } else if(!strcmp(argv[1], "d")) {
    FILE * ciphertext = fopen(argv[2], "rb"); FOPEN_CHK(ciphertext)
    FILE * key_input = fopen(argv[3], "rb"); FOPEN_CHK(key_input)
    FILE * plaintext = fopen(argv[4], "wb"); FOPEN_CHK(plaintext)
    size_t ciphertext_size = file_size(ciphertext);
    u8 * buf = malloc(ciphertext_size);
    fread(buf, 1, ciphertext_size, ciphertext);
    fclose(ciphertext);
    key k; read_key(key_input, &k);
    u8 * dec = malloc(ciphertext_size / 2);
    u64 decsz = kc_decrypt(&k, buf, dec, ciphertext_size);
    fwrite(dec, 1, decsz, plaintext);
    fclose(plaintext);
  } else if(!strcmp(argv[1], "g")) {
    FILE * key_output = fopen(argv[2], "wb"); FOPEN_CHK(key_output)
    key k = kc_keygen();
    fwrite(&k.p, 1, 128, key_output);
    fwrite(&k.b, 1, 16, key_output);
    fwrite(&k.mt, 1, 624 * 4, key_output);
    fflush(key_output);
    fclose(key_output);
  } else {
    fprintf(stderr,
      "Usage:\n"
      "  %s [e|d] [input] [key] [output]\n"
      "  %s g [key output]\n", argv[0], argv[0]);
  }
}