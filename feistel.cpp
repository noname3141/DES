#include "main.hpp"
#include "des_table.hpp"

uint32_t snap(uint64_t n, int offset){
    return (uint32_t)(n >> offset) & 0xFFFFFFFFULL;
}

void rnEnc(uint64_t pln_txt, std::vector<uint64_t>& cip_vec, const std::vector<Key>& keys, int idx){
    uint64_t val = pln_txt;
    for(int i = 0; i < ROUNDS; i++){
        Key k = keys[i];
        uint64_t ctx = val;
        uint32_t prev_l = snap(ctx, 32);
        uint32_t new_r = prev_l ^ feistel_f(snap(ctx, 0), k);
        val = snap(ctx, 0);
        val = (val << 32) + new_r;
    }
    cip_vec[idx] = val;
}

void rnDec(uint64_t cip_txt, std::vector<uint64_t>& msg_vec, const std::vector<Key>& keys, int idx){
    uint64_t val = cip_txt;
    for(int i = ROUNDS - 1; i >= 0; i--){
        Key k = keys[i];
        uint64_t ctx = val;
        uint64_t new_l = snap(ctx, 0) ^ feistel_f(snap(ctx, 32), k);
        val = snap(ctx, 32);
        val = (new_l << 32) + val;
    }
    msg_vec[idx] = val;
}
