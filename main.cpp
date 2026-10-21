#include "main.hpp"

bool generate_secure_bytes(unsigned char* buffer, size_t buffer_size) {
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    
    if (!urandom) {
        return false;
    }
    
    urandom.read(reinterpret_cast<char*>(buffer), buffer_size);
    
    return urandom.gcount() == static_cast<std::streamsize>(buffer_size);
}

Key gen(){
    Key k;
    k.size = 56;
    unsigned char des_key[8];
    k.key = 0u; 
    if (generate_secure_bytes(des_key, sizeof(des_key))) {
        std::cout << "Secure DES Key generated successfully via /dev/urandom:\n";
        for (int i = 0; i < 8; i++) {
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

Info* enc(Info*& m, Key& k, int R){
    if(!m || R <= 0)return nullptr;
    Info* c = new Info{nullptr, false};
    Node* n = new Node{0, nullptr};
    c->head = n;
    std::vector<Key> k1 = round_keys(k, R);
    for(int i = 0; i < R; i++){
        if(i == 0){
            rnEnc(m->head, c, k1[i], i + 1);
        }
        else{
            rnEnc(c->head, c, k1[i], i + 1);
        }
    }
    return c;
}

Info* dec(Info*& c, Key& k, int R){
    Info* m = new Info{nullptr, false};
    Node* n = new Node{0, nullptr};
    m->head = n;
    std::vector<Key> k1 = round_keys(k, R);
    for(int i = R - 1; i >= 0; i--){
        if(i == R - 1){
            rnDec(c->head, m, k1[i], 1);
        }
        else{
            rnDec(m->head, m, k1[i], 2);
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
    Key k = gen();
    // STYLE: Mixing C printf with C++ streams. Prefer std::cout.
    printf("%" PRIu64 "\n", k.key);
    std::string s;
    std::cin >> s;
    Node* m1 = str_to_node(s);
    Info* m = new Info{m1, false};
    Info* c = enc(m, k);
    std::string c1 = node_to_str(c->head);
    std::cout << c1;

    Info* m2 = dec(c, k);
    std::string m3 = node_to_str(m2->head);
    std::cout << "\n"<< m3;
    // MEMORY LEAK: 'm', 'c', and all allocated nodes are never freed before program exit.
    //pretty printer + ways to make my msg and cipher from str to node and node to str;
    return 0;
}
