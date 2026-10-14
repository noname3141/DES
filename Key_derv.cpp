#include "main.hpp"
#include "des_table.hpp"

void shift(uint32_t& k, int r_no){
    for(int i = 0; i < DES::SHIFTS[r_no]; i++){
        uint32_t x = k & 0x08000000;
        k = ((k << 1) | (x >> 27)) & 0x0FFFFFFF; // Because 'k' is never masked with 0x0FFFFFFF, bit 28 remains set and corrupts subsequent shifts!
    }
}

std::pair<uint32_t, uint32_t> permone(Key k){ //produces c and d for the first round.
    std::pair<uint32_t, uint32_t> a;
    uint32_t p1 = 0u;
    for(int i = 0; i < 56; i++){
        int s_bit = DES::PC1[i];
        // NOTE: PC-1 requires a 64-bit key input. If 'k' only has 56 bits in bits 0..55,
        // bits 56..63 are zero, causing bits mapped from positions 1..8 to be 0!
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

Key permtwo(std::pair<uint32_t, uint32_t>& a, int r_no){
    shift(a.first, r_no);
    shift(a.second, r_no);
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

// IMPROVEMENT: Derv is dead code; it is never declared in main.hpp or called.
Key Derv(Key k, int r_no){
    std::vector<Key> a = permone(k);
    Key rkey = permtwo(a, r_no);
    return rkey;
}

std::vector<Key> round_keys(Key k, int r_no){
    std::vector<Key> r_keys;
    std::pair<uint32_t, uint32_t> cd = permone(k);
    for(int i = 0; i < r_no; i++){
        // CRITICAL BUG: In standard DES, key shifts are CUMULATIVE across rounds.
        // Here, 'cd' is passed unmutated into permtwo on every iteration.
        // Because of this and the bug in permtwo, ALL ROUND KEYS ARE IDENTICAL!
        Key k1 = permtwo(cd, i);
        r_keys.push_back(k1);
    }
    return r_keys;
}
//done
