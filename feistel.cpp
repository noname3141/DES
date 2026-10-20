#include "main.hpp"
#include "des_table.hpp"

uint32_t nLeft(Node*& n){
    // CRITICAL CRYPTO BUG: In 64-bit big-endian representation, the LEFT half is the UPPER 32 bits:
    // '(n->ctx >> 32) & 0xFFFFFFFFULL'.
    // Casting to uint32_t takes the LOWER 32 bits, which is actually the RIGHT half!
    return (uint32_t)n->ctx & 0xFFFFFFFFULL;
}

// make it a void fn and pass both a cip node and a msg node to it.
// SYNTAX: Stray backslash '\' at the end of line.
Info* rnEnc(Node* n, Key& k){ \
    //k is already a round key
    Info* c = new(Info);
    Node* n1 = new(Node);
    c->head = n1;
    Node* ptr = c->head;
    while(n != nullptr){
        uint32_t nlft = nLeft(n);
        uint32_t nrgt = feistel_f(n->ctx, k);
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
Info* rnDec(Node* n, Key& k){
    Info* m = new(Info);
    Node* n1 = new(Node);
    m->head = n1;
    Node* ptr = m->head;
    while(n != nullptr){
        uint32_t nlft = nLeft(n);
        uint32_t nrgt = feistel_f(n->ctx, k);
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
