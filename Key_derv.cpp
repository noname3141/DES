#include "main.hpp"
#include "des_table.hpp"

void shift(uint32_t& k, int r_no){
    for(int i = 0; i < DES::SHIFTS[r_no]; i++){
        uint32_t x = k & 0x08000000;
        k = ((k << 1) | (x >> 27)) & 0x0FFFFFFF;
    }
}

std::pair<uint32_t, uint32_t> permone(Key k){ //produces c and d for the first round.
    std::pair<uint32_t, uint32_t> a;
    uint32_t p1 = 0u;
    for(int i = 0; i < 56; i++){
        int s_bit = DES::PC1[i];
        unsigned int b = (k.key >> (64 - s_bit)) & 1ULL;
        p1 = (p1 << 1) | b;
        if(i == 27){
            a.first = p1;
            p1 = 0u; // imp because if not done D0 will have non empty bits after its 28 bits which might corrupt it in round shift.
        }
        else if(i == 55){
            a.second = p1;
        }
    }
    return a;
}

Key permtwo(std::pair<uint32_t, uint32_t>& a){
    //32-bit shift overflow: '(c.key << 28)' must be 64-bit safe: '((uint64_t)c1 << 28) | d1'.
    uint64_t candd = ((uint64_t)a.first << 28) | a.second;
    uint64_t p1 = 0;
    for(int i = 0; i < 48; i++){
        int s_bit = DES::PC2[i];
        uint64_t b = (candd >> (56 - s_bit)) & 1ULL;
        p1 = (p1 << 1) | b;
    }
    Key x;
    x.size = 48;
    x.key = p1;
    return x;
}

std::vector<Key> round_keys(Key k, int rs){
    std::vector<Key> r_keys;
    std::pair<uint32_t, uint32_t> cd = permone(k);
    for(int i = 0; i < rs; i++){
        shift(cd.first, i);
        shift(cd.second, i);
        Key k1 = permtwo(cd);
        r_keys.push_back(k1);
    }
    return r_keys;
}
//done
