#ifndef MAIN_HPP
#define MAIN_HPP
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <cinttypes>
#include <cstdint>
#include <random>
#include <unistd.h>
#include <iomanip>

typedef struct ListNode{
    uint64_t ctx;
    ListNode* nx;
} Node;

typedef struct{
    uint64_t key;
    int size;
} Key;

typedef struct{
    ListNode* head;
    bool pad;
} Info;

//feistel
void rnEnc(Node* N, Info* c, Key& k, int r_no);
void rnDec(Node* N, Info* m, Key& k, int r_no);
uint32_t nLeft(const uint64_t n);

//blockfn
uint32_t feistel_f(uint32_t ctx, Key& k);
uint32_t sub(uint64_t D);
uint64_t expPerm(uint32_t ctx);
uint64_t xor_round_key(uint64_t E, Key k);

//Key_derv
std::pair<uint32_t, uint32_t> permone(Key k);
void shift(uint32_t& k, int r);
Key permtwo(std::pair<uint32_t, uint32_t>& K);
std::vector<Key> round_keys(Key k, int r_no);

//main
#define ROUNDS 16
bool generate_secure_bytes(unsigned char* buffer, size_t buffer_size);
Key gen();
Node* str_to_node(const std::string& s);
std::string node_to_str(Node* head);
Info* enc(Info*& m, Key& k, int R = ROUNDS);
Info* dec(Info*& c, Key& k, int R = ROUNDS);

#endif
