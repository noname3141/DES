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
    std::vector<uint64_t> v;
    Info* c = new Info{v, false};
    std::vector<Key> k1 = round_keys(k, R);
    for(int i = 0; i < R; i++){
        rnEnc(m->ctx, c, k1[i], i + 1);
    }
    return c;
}

Info* dec(Info*& c, Key& k, int R){
    std::vector<uint64_t> v;
    Info* m = new Info{v, false};
    std::vector<Key> k1 = round_keys(k, R);
    for(int i = R - 1; i >= 0; i--){
        rnDec(c->ctx, m, k1[i], R - i);
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
    std::cout << k.key << "\n";

    std::string s;
    std::getline(std::cin, s);
    
    std::vector<uint64_t> m1 = str_to_vec(s);
    Info* m = new Info{m1, false};
    Info* c = enc(m, k);
    
    std::string c1 = vec_to_str(c->ctx);
    std::cout << c1;

    Info* m2 = dec(c, k);
    std::string m3 = vec_to_str(m2->ctx);
    
    std::cout << "\n"<< m3 << "\n";
    return 0;
}
