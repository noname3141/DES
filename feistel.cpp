#include "main.hpp"
#include "des_table.hpp"

uint32_t low32(uint64_t n, int offset){
    return (uint32_t)(n >> offset) & 0xFFFFFFFFULL;
}

void rnEnc(std::vector<uint64_t>& v, Info* c, Key& k, int r_no){
    int x = v.size();
    const std::vector<uint64_t>& ptr = (r_no == 1)? v : c->ctx;
    for(int i = 0; i < x; i++){
        uint64_t ctx = ptr[i];
        uint32_t prev_l = low32(ctx, 32);
        uint32_t new_r = prev_l ^ feistel_f(ctx, k);
        uint64_t val = low32(ctx, 0);
        val = (val << 32) + new_r;
        if(r_no == 1){
            c->ctx.push_back(val);
        }
        else{
            c->ctx[i] = val;
        }
    }
}

void rnDec(std::vector<uint64_t>& v, Info* m, Key& k, int r_no){
    int x = v.size();
    const std::vector<uint64_t>& ptr = (r_no == 1)? v : m->ctx;
    for(int i = 0; i < x; i++){
        uint64_t ctx = ptr[i];
        uint64_t new_r = low32(ctx, 0) ^ feistel_f(ctx >> 32, k);
        uint64_t val = low32(ctx, 32);
        val = (new_r << 32) + val;
        if(r_no == 1){
            m->ctx.push_back(val);
        }
        else{
            m->ctx[i] = val;
        }
    }
}
