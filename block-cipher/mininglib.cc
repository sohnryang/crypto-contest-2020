#include "mininglib.h"

#include <algorithm>
#include <vector>

std::vector<int> mine_byte(std::vector<unsigned char> iv,
                           std::vector<unsigned char> ciphertext, int block,
                           int blockpos) {
  struct CTX ctx;
  ctx.IV = new unsigned char[iv.size()];
  std::copy(iv.begin(), iv.end(), ctx.IV);
  ctx.cipher_length = ciphertext.size() * sizeof(unsigned char);
  ctx.ciphertext = new unsigned char[ciphertext.size()];
  int bytepos = block * 16 + blockpos;
  std::vector<int> result;
  for (int i = 0; i <= 0xff; ++i) {
    ciphertext[bytepos] = (unsigned char)i;
    std::copy(ciphertext.begin(), ciphertext.end(), ctx.ciphertext);
    int padding_verdict = Dec_CTX(&ctx);
    if (padding_verdict == 0) result.push_back(i);
  }
  return result;
}
