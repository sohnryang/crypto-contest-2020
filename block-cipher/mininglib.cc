#include "mininglib.h"

#include <vector>

std::vector<int> mine_byte(CTX* ctx, int block, int blockpos) {
  int bytepos = block * 16 + blockpos;
  std::vector<int> result;
  for (int i = 0; i <= 0xff; ++i) {
    ctx->ciphertext[bytepos] = (unsigned char)i;
    int padding_verdict = Dec_CTX(ctx);
    if (padding_verdict == 0) result.push_back(i);
  }
  return result;
}
