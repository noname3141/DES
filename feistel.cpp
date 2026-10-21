#include "main.hpp"
#include "des_table.hpp"

uint32_t nLeft(uint64_t n){
    return (uint32_t)n & 0xFFFFFFFFULL;
}

void rnEnc(Node* n, Info* c, Key& k, int r_no){
    Node* ptr = (r_no == 1)? n : c->head;
    Node* des = c->head;
    while(ptr != nullptr){
        uint32_t plft = nLeft(ptr->ctx >> 32);
        uint32_t nrgt = plft ^ feistel_f(ptr->ctx, k);
        uint64_t val = nLeft(ptr->ctx);
        val = (val << 32) + nrgt;
        des->ctx = val;
        if(r_no == 1 && ptr->nx != nullptr){
            des->nx = new Node{0, nullptr};
        }
        ptr = ptr->nx;
        des = des->nx;
    }
}

void rnDec(Node* n, Info* m, Key& k, int r_no){
    Node* ptr = (r_no == 1)? n : m->head;
    Node* des = m->head;
    while(ptr != nullptr){
        uint64_t nrgt = nLeft(ptr->ctx) ^ feistel_f(ptr->ctx >> 32, k);
        uint64_t val = nLeft(ptr->ctx >> 32);
        val = (nrgt << 32) + val;
        des->ctx = val;
        if(r_no == 1 && ptr->nx != nullptr){
            des->nx = new Node{0, nullptr};
        }
        ptr = ptr->nx;
        des = des->nx;
    }
}
