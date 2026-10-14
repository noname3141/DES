#ifndef MAIN_HPP
#define MAIN_HPP
// ERROR: Missing '#define MAIN_HPP'. Without it, this header guard does not prevent multiple inclusions.
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <cinttypes>
#include <cstdint>
#include <random>
#include <unistd.h>
#include <iomanip>

//allowing us to store any size of msg which can later be defined as padded or not if
// STYLE: 'typedef struct' is redundant in C++; simply use 'struct Node { ... };'.
// IMPROVEMENT: Singly-linked list causes 100% pointer overhead (8 bytes data + 8 bytes pointer)
// and heap fragmentation. Prefer std::vector<uint64_t> or std::vector<uint8_t>.
typedef struct ListNode{
    uint64_t ctx;
    ListNode* nx;
} Node;

//key is size_t because we are going to derive 48 bit keys from a 56 bit key.
typedef struct{
    uint64_t key;
    int size;
} Key;

// IMPROVEMENT: Msg and Cip are structurally identical. Having two separate structs is redundant.
typedef struct{
    ListNode* head;
    bool pad;
} Msg;

typedef struct{
    ListNode* head;
    bool pad;
} Cip;

//feistel
Cip* RnEnc(Node* N, Key& k);
// IMPROVEMENT: RnKey is dead code; it is defined in feistel.cpp but never called.
Key RnKey(uint32_t c, uint32_t d, int r);
Msg* RnDec(Node* N, Key& k);
// STYLE: Pass as 'const Node* n'. Passing non-const 'Node*&' prevents passing rvalues/temporaries.
uint32_t nLeft(Node*& n);

//blockfn
// STYLE: Function computes entire Feistel f(R, K); name should be 'feistel_f' or 'f_function'.
uint32_t nRight(Node*& n, Key& k);
// STYLE: Pass 64-bit values by value: 'uint64_t D', not 'size_t& D' (size_t is 32-bit on 32-bit CPUs).
uint32_t Sub(size_t& D);
// IMPROVEMENT: Should take a 32-bit right half (uint32_t R), decoupling it from Node*.
size_t ExpPerm(Node*& N);
// STYLE: Cryptic name. Rename to 'xor_round_key' and pass integers by value.
size_t XwEK(size_t& E, Key& k);

//Key_derv
// STYLE: Returning a vector for 2 halves adds heap allocation. Prefer std::pair or a struct.
std::pair<uint32_t, uint32_t> permone(Key k);
void shift(uint32_t& k, int r);
Key permtwo(std::pair<uint32_t, uint32_t>& K, int r);
std::vector<Key> round_keys(Key k, int r_no);

//main
#define ROUNDS 16
bool generate_secure_bytes(unsigned char* buffer, size_t buffer_size);
Key Gen();
// STYLE: Default argument 'int R = ROUNDS' should be declared here in the header.
Cip* Enc(Msg*& m, Key& k, int R);
Msg* Dec(Cip*& c, Key& k, int R);

#endif
