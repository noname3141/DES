# DES (Data Encryption Standard)

A C++ implementation of the DES block cipher operating on 64-bit blocks using a standard 16-round Feistel network.

## Overview

The program reads an input string from standard input, packs it into 64-bit (`uint64_t`) blocks, encrypts the blocks using DES round subkeys generated from `/dev/urandom`, and decrypts the resulting ciphertext back to plaintext to verify round invertibility.

### Pipeline

1. **Key Schedule (`Key_derv.cpp`)**
   - A 64-bit key is sampled from `/dev/urandom`.
   - **PC-1 (Permuted Choice 1)**: Strips 8 parity bits to extract the 56 active key bits, split into two 28-bit halves ($C_0, D_0$).
   - **Round Shifts**: In each of the 16 rounds, both halves undergo cumulative circular left shifts (by 1 or 2 bits according to the standard DES shift schedule).
   - **PC-2 (Permuted Choice 2)**: Compresses the shifted 56-bit state down to a 48-bit subkey ($K_i$) per round.

2. **Feistel Round Function $f(R, K)$ (`blockfn.cpp`)**
   - **Expansion Permutation ($E$)**: Expands the 32-bit right half of the block into 48 bits.
   - **Subkey Mixing**: XORs the 48-bit expanded block with the 48-bit round subkey.
   - **S-Box Substitution**: Splits the 48-bit result into eight 6-bit chunks. Each chunk addresses one of the eight standard DES S-boxes (outer bits select row 0–3, inner 4 bits select column 0–15) producing eight 4-bit nibbles recombined into 32 bits.
   - **Permutation ($P$)**: Permutes the 32-bit S-box output via a straight P-box.

3. **Feistel Structure (`feistel.cpp`)**
   - Divides each 64-bit block into 32-bit left ($L$) and right ($R$) halves.
   - For round $i \in [1, 16]$:
     $$L_i = R_{i-1}$$
     $$R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$$
   - Decryption runs the exact same Feistel rounds in reverse order ($K_{16}$ down to $K_1$).

## File Structure

- [main.hpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.hpp) — Struct definitions (`Key`, `Info`), function declarations, and constants.
- [main.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/main.cpp) — Entry point, CSPRNG key sampling via `/dev/urandom`, block conversion, and encryption/decryption drivers.
- [feistel.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/feistel.cpp) — Round-level Feistel transformation functions (`rnEnc`, `rnDec`, `snap`).
- [blockfn.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/blockfn.cpp) — Feistel round function $f(R, K)$ ($E$-expansion, key XOR, S-box substitution, $P$-box).
- [Key_derv.cpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/Key_derv.cpp) — Key derivation and scheduling (PC-1, bit shifting, PC-2).
- [des_table.hpp](file:///home/vinayak/Vinayak/projects/cryp/BlockCiphers/DES/des_table.hpp) — Standard DES lookup tables (PC-1, PC-2, E, P, S-boxes, shift schedule, IP, FP).

## Build and Run

### Prerequisites

- C++17 compatible compiler (`g++` or `clang++`)
- Linux / Unix environment (uses `/dev/urandom` for key generation)

### Compilation

```bash
g++ -Wall -Wextra -std=c++17 main.cpp feistel.cpp Key_derv.cpp blockfn.cpp -o des
```

### Usage

Run the binary and enter a string:

```bash
./des
```

Example session:

```text
Secure DES Key generated successfully via /dev/urandom:
61 20 98 D3 8A 7D 0E E0 
6998761855262723808
HelloWorld
2 Ѯ QĽW 
HelloWorld      
```

## Implementation Notes

- **Block Storage**: Blocks are stored and operated on as `std::vector<uint64_t>`.
- **Padding**: Strings are zero-padded to the nearest 8-byte boundary. PKCS#7 padding is not currently implemented.
- **Initial and Final Permutations**: The `IP` and `FP` ($IP^{-1}$) tables are defined in `des_table.hpp`, but data-level permutations are currently bypassed in the block pipeline.
- **Security Notice**: DES has an effective key length of 56 bits and is insecure for production use. This implementation is strictly for educational purposes.
