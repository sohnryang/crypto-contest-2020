/*
 * collisions.cc
 * Code for finding collisions
 */

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

#include "mininglib.h"

int main() {
  std::ifstream cipher_file("./ciphertext.txt");
  cipher_file >> std::hex;
  int cipher_byte;
  std::vector<unsigned char> cipher;
  while (cipher_file >> cipher_byte) cipher.push_back(cipher_byte);
  cipher_file.close();

  std::ifstream iv_file("./iv.txt");
  iv_file >> std::hex;
  int iv_byte;
  std::vector<unsigned char> iv;
  while (iv_file >> iv_byte) iv.push_back(iv_byte);
  iv_file.close();

  std::vector<std::vector<int>> collisions;
  for (int i = 0; i < cipher.size(); ++i) {
    if (i != 0 && i % 16 == 0) std::cout << std::endl;
    std::vector<int> mined = mine_byte(iv, cipher, i / 16, i % 16);
    std::cout << mined.size() << " ";
    collisions.push_back(mined);
  }
  std::cout << std::endl;

  for (int i = 0; i < 16 * 29; ++i) {
    std::cout << "Collision for block " << i / 16 << " byte " << i % 16 << ": ";
    for (int byte : collisions[i]) {
      std::cout << std::hex;
      if (byte != cipher[i]) std::cout << "0x" << byte << " ";
      else std::cout << "(" << "0x" << byte << ") ";
      std::cout << std::dec;
    }
    std::cout << std::endl;
  }

  return 0;
}
