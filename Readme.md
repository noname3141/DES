# DES (Data Encryption Standard) in CBC Mode

A C++ implementation of the DES block cipher operating on 64-bit blocks using a standard 16-round Feistel network and Cipher Block Chaining (CBC) mode.

## Overview

The program reads an input string from standard input, divides it into 64-bit (`uint64_t`) blocks using big-endian byte-packing, encrypts the blocks using DES in **Cipher Block Chaining (CBC)** mode with a randomly generated 64-bit Initialization Vector (IV) and key sampled from `/dev/urandom`, and decrypts the resulting ciphertext back to plaintext to verify round invertibility.

### Cryptographic Pipeline

```
Plaintext Block P_i
       │
       ▼
     ( X ) <── IV (for i=0) or Ciphertext Block C_{i-1} (for i>0)
       │
       ▼
┌──────────────┐
│ 16-Round DES │ <── Round Subkeys K_0 ... K_15 (derived from Key)
│   Feistel    │
└──────────────┘
       │
       ▼
Ciphertext Block C_i (Printed as 16-character hex)
```

1. **Key Schedule ([`Key_derv.cpp`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp))**
   - A 64-bit key is securely sampled from `/dev/urandom` using [`gen`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L15-L37) and [`generate_secure_bytes`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L3-L13).
   - **PC-1 (Permuted Choice 1)**: Strips 8 parity bits via [`permone`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L11-L27) to produce two 28-bit halves ($C_0, D_0$), isolating the 56 active key bits.
   - **Round Shifts**: In each of the 16 rounds, both halves undergo circular left shifts according to the standard DES schedule [`DES::SHIFTS`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L81-L84) (1 bit for rounds 0, 1, 8, 15; 2 bits for others) via [`shift`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L4-L9).
   - **PC-2 (Permuted Choice 2)**: Compresses the 56-bit shifted halves into a 48-bit subkey ($K_i$) per round via [`permtwo`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L29-L42).
   - All 16 round subkeys are generated ahead of time via [`round_keys`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L44-L54).

2. **Feistel Round Function $f(R, K)$ ([`blockfn.cpp`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp))**
   - **Expansion Permutation ($E$)**: Expands the 32-bit right half of the block into 48 bits using [`expPerm`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L8-L16) and [`DES::E`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L21-L30).
   - **Subkey Mixing**: XORs the 48-bit expanded block with the 48-bit round subkey using [`xor_round_key`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L4-L6).
   - **S-Box Substitution**: Splits the 48-bit value into eight 6-bit segments via [`sub`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L18-L28). Outer bits select the row (0–3) and inner 4 bits select the column (0–15) from [`DES::SBOX`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L87-L148), yielding eight 4-bit nibbles recombined into 32 bits.
   - **Straight Permutation ($P$)**: Permutes the 32-bit S-box output using [`DES::P`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L33-L42).

3. **Feistel Network Execution ([`feistel.cpp`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp))**
   - Operates block-by-block on 64-bit words:
     - Splits each block into 32-bit left ($L$) and right ($R$) halves using [`snap`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp#L4-L6).
     - **Encryption ([`rnEnc`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp#L8-L19))**: Runs 16 rounds ($i \in [0, 15]$):
       $$L_{i+1} = R_i$$
       $$R_{i+1} = L_i \oplus f(R_i, K_i)$$
       Final block recombined as $(L_{16} \ll 32) \mid R_{16}$.
     - **Decryption ([`rnDec`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp#L21-L30))**: Inverts the rounds in reverse subkey order ($i \in [15, 0]$):
       $$L_i = R_{i+1} \oplus f(L_{i+1}, K_i)$$
       $$R_i = L_{i+1}$$
       Final block recombined as $(L_0 \ll 32) \mid R_0$.

4. **Cipher Block Chaining (CBC) Mode ([`main.cpp`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp))**
   - Samples a 64-bit Initialization Vector (`IV`) from `/dev/urandom`.
   - **Encryption ([`enc`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L39-L52))**:
     $$C_0 = E_K(P_0 \oplus \text{IV})$$
     $$C_i = E_K(P_i \oplus C_{i-1}) \quad \text{for } i \ge 1$$
   - **Decryption ([`dec`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L54-L67))**:
     $$P_0 = D_K(C_0) \oplus \text{IV}$$
     $$P_i = D_K(C_i) \oplus C_{i-1} \quad \text{for } i \ge 1$$

---

## File Structure

- [main.hpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.hpp) — Data structures ([`Key`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.hpp#L17-L20), [`Info`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.hpp#L22-L25)), core function prototypes, and constants (`ROUNDS = 16`).
- [main.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp) — CLI flag parsing (`-k` / `--key`), CSPRNG key/IV generation ([`generate_secure_bytes`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L3-L13), [`gen`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L15-L37)), CBC encryption/decryption drivers ([`enc`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L39-L52), [`dec`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L54-L67)), string-to-vector block conversion ([`str_to_vec`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L69-L85), [`vec_to_str`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L87-L98)), and hexadecimal block formatting ([`uint64ToHex`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L100-L105)).
- [feistel.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp) — Block-level 16-round Feistel transformations ([`rnEnc`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp#L8-L19), [`rnDec`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp#L21-L30)) and 32-bit word extraction ([`snap`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp#L4-L6)).
- [blockfn.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp) — Feistel round function ([`feistel_f`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L31-L46)), expansion permutation ([`expPerm`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L8-L16)), round key mixing ([`xor_round_key`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L4-L6)), and S-box substitution ([`sub`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp#L18-L28)).
- [Key_derv.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp) — Subkey scheduling: PC-1 permutation ([`permone`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L11-L27)), circular shifts ([`shift`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L4-L9)), PC-2 permutation ([`permtwo`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L29-L42)), and 16-round subkey schedule builder ([`round_keys`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp#L44-L54)).
- [des_table.hpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp) — Standard DES lookup tables and permutation matrices ([`DES::IP`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L9-L18), [`DES::E`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L21-L30), [`DES::P`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L33-L42), [`DES::FP`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L45-L54), [`DES::PC1`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L57-L66), [`DES::PC2`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L69-L78), [`DES::SHIFTS`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L81-L84), [`DES::SBOX`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp#L87-L148)).

---

## Build and Run

### Prerequisites

- C++17 compatible compiler (`g++` or `clang++`)
- Linux / Unix environment (uses `/dev/urandom` for cryptographic entropy)

### Compilation

```bash
g++ -Wall -Wextra -std=c++17 main.cpp feistel.cpp Key_derv.cpp blockfn.cpp -o des
```

### Usage

#### Standard Mode

Run the binary and provide the plaintext string:

```bash
./des
```

Example session:

```text
Enter Plaintext: HelloWorld

-------------------------------------------------------
Secure DES Key generated successfully via /dev/urandom:
-------------------------------------------------------
Generated Key (hex) : 57 03 85 E5 32 D7 60 A6 
Generated Cipertext Blocks: 3727bb64806db179 dcb508742ac4719c 

Original Plaintext : HelloWorld
Retrieved Plaintext: HelloWorld      
```

#### Verbose / Key Inspection Mode (`-k` or `--key`)

Pass `-k` or `--key` to display the sampled DES encryption key, byte count summary, and verification confirmation:

```bash
./des -k
```

Example session:

```text
-------------------------------------------------------
Secure DES Key generated successfully via /dev/urandom:
-------------------------------------------------------
Generated Key (hex) : 95 B5 5D F0 36 99 53 B9 

Enter Plaintext: HelloWorld

---------------------------------------
Successfully encrypted 10 bytes of data 
---------------------------------------

-------------------------------------------------------
Secure DES Key generated successfully via /dev/urandom:
-------------------------------------------------------
Generated Key (hex) : 0C B6 54 04 56 EF 0C 35 
Generated Cipertext Blocks: 4d87e0eb264430e4 8483a01749142dcb 

Original Plaintext : HelloWorld
Retrieved Plaintext: HelloWorld      

------------------------------
| Encryption Scheme Verified |
------------------------------
```

---

## Implementation Details

- **Block Vector Storage**: Plaintext is chunked into 64-bit blocks represented as a `std::vector<uint64_t>`.
- **Endianness & Bit Packing**: Bytes are packed big-endian into 64-bit words via [`str_to_vec`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L69-L85) (`s[i + j] << (8 * (7 - j))`) and unpacked symmetrically via [`vec_to_str`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L87-L98).
- **Hexadecimal Representation**: Ciphertext blocks are formatted using [`uint64ToHex`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp#L100-L105) into 16-character zero-padded hexadecimal strings.
- **CBC Mode & IV**: Each encryption operation samples a unique 64-bit Initialization Vector (`IV`) from `/dev/urandom`, chaining each ciphertext block into the subsequent plaintext block to eliminate codebook patterns.
- **Padding**: Plaintext chunks shorter than 8 bytes are zero-padded to fill the 64-bit boundary.
- **Permutation Tables**: Initial Permutation (`IP`) and Final Permutation (`FP` / $IP^{-1}$) lookup matrices are defined in [`des_table.hpp`](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp), while data-level permutations are currently bypassed in the block pipeline.

> [!NOTE]
> The effective key length of DES is 56 bits (with 8 parity bits dropped by PC-1). This implementation is intended for educational and cryptographic analysis purposes.
