#ifndef __MININGLIB_H
#define __MININGLIB_H

#include <vector>

#include "decryptor.h"

std::vector<int> mine_byte(std::vector<unsigned char> iv,
                           std::vector<unsigned char> ciphertext, int block,
                           int blockpos);
#endif
