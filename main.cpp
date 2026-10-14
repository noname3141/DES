#include "main.hpp"

bool generate_secure_bytes(unsigned char* buffer, size_t buffer_size) {
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    
    if (!urandom) {
        return false;
    }
    
    urandom.read(reinterpret_cast<char*>(buffer), buffer_size);
    
    return urandom.gcount() == static_cast<std::streamsize>(buffer_size);
}

Key Gen(){
    Key k;
    k.size = 56;
    unsigned char des_key[8];
    k.key = 0u; 
    if (generate_secure_bytes(des_key, sizeof(des_key))) {
        std::cout << "Secure DES Key generated successfully via /dev/urandom:\n";
        for (int i = 0; i < 8; ++i) {
            printf("%02X ", des_key[i]);
            k.key += (uint8_t)des_key[i];
            if(i != 7)k.key <<= 8;
        }
        std::cout << "\n";
    } else {
        std::cerr << "Critical Error: Failed to safely sample entropy pool.\n";
    }
    return k;
}

Cip* Enc(Msg*& m, Key& k, int R = ROUNDS){
    // MEMORY LEAK: 'c' and 'n' allocated here are immediately overwritten in loop iteration 0.
    Cip* c = new (Cip);
    Node* n = new(Node);
    c->head = n;
    c->pad = m->pad;
    std::vector<Key> k1 = round_keys(k, R);
    for(int i = 0; i < R; i++){
        if(i == 0){
            // MEMORY LEAK: Overwrites 'c' with the new allocation from RnEnc, leaking the initial 'c' and 'n'.
            c = RnEnc(m->head, k1[i]);
        }
        else{
            // MEMORY LEAK: RnEnc allocates a whole new Cip and Node list each round.
            // The previous round's 'c' and all its nodes are leaked on every iteration.
            c = RnEnc(c->head, k1[i]);
        }
    }
    return c;
}

Msg* Dec(Cip*& c, Key& k, int R = ROUNDS){
    Msg* m = new (Msg);
    Node* n = new(Node);
    m->head = n;
    m->pad = c->pad;
    std::vector<Key> k1 = round_keys(k, R);
    // CRITICAL BUG 1: 'i++' instead of 'i--'! Starts at (R - 1) and checks (i >= 0),
    // causing an INFINITE LOOP and eventual out-of-bounds access on k1[i] when i >= R!
    for(int i = R - 1; i >= 0; i++){
        // CRITICAL BUG 2: In decryption, the first round is (R - 1), NOT 0.
        // On iteration 0 (i = R - 1), it takes the 'else' branch, passing uninitialized dummy 'm->head'.
        if(i == 0){
            m = RnDec(c->head, k1[i]);
        }
        else{
            m = RnDec(m->head, k1[i]);
        }
    }
    return m;
}

Node* str_to_node(const std::string& s) {
    Node* head = nullptr;
    Node* tail = nullptr;

    if(s.size() == 0) return nullptr;
    for (size_t i = 0; i < s.size(); i += 8) {
        uint64_t block = 0;

        size_t remaining = std::min<size_t>(8, s.size() - i);

        // IMPROVEMENT: No standard padding (e.g. PKCS#7). Trailing bytes are simply 0,
        // making it impossible upon decryption to distinguish trailing nulls from padding.
        for (size_t j = 0; j < remaining; ++j) {
            block |= (uint64_t)(unsigned char)s[i + j] << (8 * (7 - j));
        }

        Node* n = new Node{block, nullptr};

        if (!head) {
            head = n;
        } else {
            tail->nx = n;
        }

        tail = n;
    }

    return head;
}

std::string node_to_str(Node* head) {
    std::string result;

    for (Node* cur = head; cur != nullptr; cur = cur->nx) {
        for (int j = 7; j >= 0; --j) {
            // IMPROVEMENT: Extracts full 8 bytes unconditionally; padding null bytes will be appended to the string.
            char c = (char)((cur->ctx >> (8 * j)) & 0xFF);
            result += c;
        }
    }

    return result;
}

int main(){
    //main aim is to get any length input and implement a DES that divides the message into blocks of size 64 bits each and operates on them for which i could possibly implement a data structure which is kinda like a linked list
    Key k = Gen();
    // STYLE: Mixing C printf with C++ streams. Prefer std::cout.
    printf("%" PRIu64 "\n", k.key);
    std::string s;
    // IMPROVEMENT: 'cin >> s' stops at whitespace. Use 'std::getline(cin, s)' to read entire lines.
    std::cin >> s;
    Node* m1 = str_to_node(s);
    // CRITICAL BUG: 'sizeof(m)' is sizeof(Msg*) = 8 bytes, but sizeof(Msg) is 16 bytes!
    // This under-allocates memory and causes heap corruption when accessing m->pad.
    // STYLE: Avoid 'malloc' in C++; use 'new Msg;' or value semantics.
    Msg* m = (Msg*)malloc(sizeof(m));
    m->head = m1;
    // ERROR: m->pad is uninitialized!
    Cip* c = Enc(m, k);
    std::string c1 = node_to_str(c->head);

    // MEMORY LEAK: 'm', 'c', and all allocated nodes are never freed before program exit.
    //pretty printer + ways to make my msg and cipher from str to node and node to str;
    return 0;
}
