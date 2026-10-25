#ifndef MAIN_HPP
#define MAIN_HPP
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <random>
#include <unistd.h>
#include <iomanip>

//make the input string into a vector instead.

typedef struct{
    uint64_t key;
    int size;
} Key;

typedef struct{
    std::vector<uint64_t> ctx;
    bool pad;
} Info;

//feistel
void rnEnc(uint64_t pln_txt, std::vector<uint64_t>& cip_vec,const std::vector<Key>& keys, int idx);
void rnDec(uint64_t cip_txt, std::vector<uint64_t>& msg_vec,const std::vector<Key>& keys, int idx);
uint32_t snap(const uint64_t n, int offset);

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
Key gen(bool k);
std::vector<uint64_t> str_to_vec(const std::string& s);
std::string vec_to_str(const std::vector<uint64_t>& v);
std::string uint64ToHex(const std::vector<unsigned char>& v);
Info* enc(const Info* m, Key& k, uint64_t IV, int R = ROUNDS);
Info* dec(const Info* c, Key& k, uint64_t IV, int R = ROUNDS);

#endif
