/*
 * mine_bytes.cc
 * Mine bytes from the ciphertext using padding oracle
 */

#include <Windows.h>

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "mininglib.h"

int main(int argc, char* argv[]) {
  assert(argc == 3);
  int block = std::stoi(argv[1]);
  int blockpos = std::stoi(argv[2]);
  int offset = block * 16 + blockpos;

  std::ifstream ciphertext_file("./ciphertext.txt");
  ciphertext_file >> std::hex;
  int ciphertext_byte;
  std::vector<unsigned char> ciphertext;
  while (ciphertext_file >> ciphertext_byte)
    ciphertext.push_back(ciphertext_byte);
  ciphertext_file.close();
  int original_byte = ciphertext[offset];

  std::ifstream iv_file("./iv.txt");
  iv_file >> std::hex;
  int iv_byte;
  std::vector<unsigned char> iv;
  while (iv_file >> iv_byte) iv.push_back(iv_byte);
  iv_file.close();

  struct CTX ctx;
  ctx.ciphertext = new unsigned char[ciphertext.size()];
  ctx.cipher_length = ciphertext.size() * sizeof(unsigned char);
  ctx.IV = new unsigned char[iv.size()];
  std::copy(iv.begin(), iv.end(), ctx.IV);

  std::vector<unsigned char> successful_attempts;
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  for (int i = 0; i <= 0xff; ++i) {
    std::cout << "Trying " << std::hex << i << "... Padding verdict: ";
    ciphertext[offset] = i;
    std::copy(ciphertext.begin(), ciphertext.end(), ctx.ciphertext);
    int verdict = Dec_CTX(&ctx);
    if (verdict == 0) {
      SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
      std::cout << "VALID";
      successful_attempts.push_back(i);
    } else {
      SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
      std::cout << "INVALID";
    }
    SetConsoleTextAttribute(hConsole, 15);
    std::cout << std::endl;
  }

  std::cout << std::endl << "Successful bytes: ";
  for (auto c : successful_attempts) {
    if (original_byte != (int)c)
      SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);
    std::cout << "0x" << (int)c << " ";
    SetConsoleTextAttribute(hConsole, 15);
  }
  std::cout << std::endl;
  return 0;
}
