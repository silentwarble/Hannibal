#ifndef UTILITY_ENCRYPTION_HELPERS_H
#define UTILITY_ENCRYPTION_HELPERS_H

#include "hannibal.h"
#include "bcrypt.h"

#include "utility_encryption_AES.h"
#include "utility_encryption_pkcs7_padding.h"
#include "utility_hashing_sha256_hmac.h"
#include "utility_rand.h"

#define IV_SIZE 16

// #define LCG_SEED 0xDEADBEEF
// UINT32 lcg_random();
// void lcg_generate_iv(char iv[IV_SIZE]);

void generate_iv(char *iv);
void bcrypt_generate_iv(char iv[IV_SIZE]);


#endif