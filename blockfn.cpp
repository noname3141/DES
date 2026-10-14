#include "main.hpp"
#include "des_table.hpp"

// IMPROVEMENT: Tightly coupled to Node*. This function should take a 32-bit integer (uint32_t R).
// STYLE: Return uint64_t instead of size_t (size_t is 32 bits on 32-bit platforms).
size_t ExpPerm(Node*& N){
    uint64_t res = 0;
    for(int i = 0; i < 48; i++){
        int s = DES::E[i];
        // NOTE: Because N->ctx is 64-bit and (32 - s) is in [0, 31], this only reads from the lower 32 bits.
        uint32_t bit = (N->ctx >> (32 - s)) & 1ULL;
        res = (res << 1) | bit;
    }
    return res;
}

// STYLE: Cryptic name ('XwEK'). Suggest 'xor_subkeys' or 'xor_round_key'.
// STYLE: Pass 64-bit primitives by value (uint64_t b, uint64_t k), not non-const reference.
size_t XwEK(size_t& b, Key& k){
    return (b & 0x0000FFFFFFFFFFFFULL) ^ (k.key & 0x0000FFFFFFFFFFFFULL);
}

// STYLE: Pass 'uint64_t D' by value instead of 'size_t& D'.
uint32_t Sub(size_t& D){
    uint32_t output = 0;
    for(int i = 0; i < 8; i++){
        // STYLE: Add parentheses for operator precedence clarity: ((D >> (42 - 6*i)) & 0x3F).
        uint8_t ch = D >> (42 - 6*i) & 0x3F;
        uint8_t row = ((ch & 0x20) >> 4) | (ch & 0x01); // bits 012345 -> row 05
        uint8_t col = (ch >> 1) & 0x0F; // bits 012345 -> col 1234
        uint8_t val = DES::SBOX[i][row][col];
        output = (output << 4) | val;
    }
    return output;
}

// MISLEADING NAME: 'nRight' does not just extract the right half;
// it executes the entire Feistel round function f(R, K). Rename to 'feistel_f'.
uint32_t nRight(Node*& N, Key& k){
    //expansion p box
    size_t bits_48 = ExpPerm(N);
    //Xor with round key
    size_t xres = XwEK(bits_48, k);
    //sboxes to convert the 48 bits back to 64
    // NOTE: Comment is inaccurate: S-boxes convert 48 bits back to 32 bits (8 * 4 bits = 32), not 64.
    uint32_t r = Sub(xres);
    //straight p box
    uint32_t res = 0;
    for(int i = 0; i < 32; i++){
        int s = DES::P[i];
        uint32_t bit = (r >> (32 - s)) & 1ULL;
        res = (res << 1) | bit;
    }
    return res;
}
