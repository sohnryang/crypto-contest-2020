#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <vector>

#include "decryptor.h"

int main() {
  Byte IV[16] = {0x22, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c,
                 0x20, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x22};
  int ciphertext_byte;
  std::vector<Byte> ciphertext;

  std::ifstream input_file("./ciphertext.txt");
  input_file >> std::hex;
  while (input_file >> ciphertext_byte)
    ciphertext.push_back((Byte)ciphertext_byte);
  input_file.close();

  std::cout << std::hex;
  for (Byte c : ciphertext) std::cout << (int)c << " ";

  struct CTX ctx1;
  ctx1.ciphertext = new Byte[ciphertext.size()];
  std::copy(ciphertext.begin(), ciphertext.end(), ctx1.ciphertext);
  ctx1.cipher_length = ciphertext.size() * sizeof(Byte);
  ctx1.IV = IV;

  int ret = Dec_CTX(&ctx1);

  if (ret == 0)
    std::cout << "valid" << std::endl;
  else
    std::cout << "invalid" << std::endl;

  return 0;
}
