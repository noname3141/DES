#include "main.hpp"
#include "des_table.hpp"

uint64_t xor_round_key(uint64_t b, Key k){
    return (b & 0x0000FFFFFFFFFFFFULL) ^ (k.key & 0x0000FFFFFFFFFFFFULL);
}

uint64_t expPerm(uint32_t ctx){
    uint64_t res = 0;
    for(int i = 0; i < 48; i++){
        int s = DES::E[i];
        unsigned int b = (ctx >> (32 - s)) & 1ULL;
        res = (res << 1) | b;
    }
    return res;
}

uint32_t sub(uint64_t D){
    uint32_t output = 0;
    for(int i = 0; i < 8; i++){
        uint8_t ch = (D >> (42 - 6*i)) & 0x3F;
        uint8_t row = ((ch & 0x20) >> 4) | (ch & 0x01); // bits 012345 -> row 05
        uint8_t col = (ch >> 1) & 0x0F; // bits 012345 -> col 1234
        uint8_t val = DES::SBOX[i][row][col];
        output = (output << 4) | val;
    }
    return output;
}

// it executes the entire Feistel round function f(R, K).
uint32_t feistel_f(uint32_t ctx, Key& k){
    //expansion p box
    uint64_t bits_48 = expPerm(ctx);
    //Xor with round key
    uint64_t xres = xor_round_key(bits_48, k);
    //sboxes to convert the 48 bits back to 32
    uint32_t r = sub(xres);
    //straight p box
    uint32_t res = 0;
    for(int i = 0; i < 32; i++){
        int s = DES::P[i];
        uint32_t bit = (r >> (32 - s)) & 1ULL;
        res = (res << 1) | bit;
    }
    return res;
}
