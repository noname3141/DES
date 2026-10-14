#include "main.hpp"
#include "des_table.hpp"

uint32_t nLeft(Node*& n){
    // CRITICAL CRYPTO BUG: In 64-bit big-endian representation, the LEFT half is the UPPER 32 bits:
    // '(n->ctx >> 32) & 0xFFFFFFFFULL'.
    // Casting to uint32_t takes the LOWER 32 bits, which is actually the RIGHT half!
    return (uint32_t)n->ctx & 0xFFFFFFFFULL;
}

// SYNTAX: Stray backslash '\' at the end of line.
Cip* RnEnc(Node* n, Key& k){ \
    //k is already a round key
    Cip* c = new(Cip);
    Node* n1 = new(Node);
    c->head = n1;
    Node* ptr = c->head;
    while(n != nullptr){
        uint32_t nlft = nLeft(n);
        uint32_t nrgt = nRight(n, k);
        // FUNDAMENTAL FEISTEL FLAW:
        // In a Feistel network round:
        //   L_next = R_prev
        //   R_next = L_prev XOR f(R_prev, K)
        // Here, nlft is R_prev and nrgt is f(R_prev, K).
        // L_prev (the upper 32 bits of n->ctx) is NEVER read and NEVER XORed!
        // It is completely discarded, destroying data irreversibly.
        uint64_t val = nlft;
        val <<= 32;
        val += nrgt;
        ptr->ctx = val;
        if(n->nx != nullptr){
            Node* n2 = new(Node);
            ptr->nx = n2;
            ptr = ptr->nx;
        }
        else{
            ptr->nx = nullptr;
        }
        n = n->nx;
    }
    return c;
}

// ERROR: RnDec is an exact copy-paste duplicate of RnEnc.
// Decryption must apply round keys in reverse and invert the Feistel operation.
Msg* RnDec(Node* n, Key& k){
    Msg* m = new(Msg);
    Node* n1 = new(Node);
    m->head = n1;
    Node* ptr = m->head;
    while(n != nullptr){
        uint32_t nlft = nLeft(n);
        uint32_t nrgt = nRight(n, k);
        uint64_t val = nlft;
        val <<= 32;
        val += nrgt;
        ptr->ctx = val;
        if(n->nx != nullptr){
            Node* n2 = new(Node);
            ptr->nx = n2;
            ptr = ptr->nx;
        }
        else{
            ptr->nx = nullptr;
        }
        n = n->nx;
    }
    return m;
}

// IMPROVEMENT: RnKey is dead code; it is never called.
Key RnKey(uint32_t c, uint32_t d, int r_no){
    shift(c, r_no);
    shift(d, r_no);

    // ERROR / OVERFLOW: 'c' is uint32_t. In C++, 'c << 28' is performed as 32-bit unsigned arithmetic.
    // Any bits above bit 3 are shifted out and lost before conversion to uint64_t!
    // Must be: '((uint64_t)c << 28) | d'.
    uint64_t val = (c << 28) | d;
    uint64_t p2 = 0;
    for(int i = 0; i < 48; i++){
        int s = DES::PC2[i];
        uint64_t b = (val >> (56 - s)) & 1ULL;
        p2 = (p2 << 1) | b;
    }
    Key ki;
    ki.size = 48;
    ki.key = p2;
    return ki;
}
