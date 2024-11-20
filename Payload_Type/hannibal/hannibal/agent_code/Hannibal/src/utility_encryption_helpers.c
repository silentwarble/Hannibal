// Credit: While I rewrote some of it, I did use some ideas from https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon

#include "utility_encryption_helpers.h"


/**
 * Using GetTickCount + RtlRandomEx shouldn't be considered
 * cryptographically secure. However, it should be adequate for
 * our purposes. It is the default in order to avoid loading bcrypt.dll. TODO: bcrypt is currently required for other things. Refactor to make optional.
 * If this is not suitable for your purposes, use bcrypt_generate_iv().
 */
SECTION_CODE void generate_iv(char *iv)
{
    HANNIBAL_INSTANCE_PTR

    ULONG seed = hannibal_instance_ptr->Win32.GetTickCount();

    for(int i = 0; i < IV_SIZE; i++){
        iv[i] = gen_random_byte(&seed);
    }
}


/**
 * Note: This code requires functions located in bcrypt.dll.
 * If having bcrypt.dll load into your process is not desirable TODO: bcrypt is currently required for other things. Refactor to make optional.
 * you will need to find an alternative way to generate a random IV.
 * Use generate_iv() or look at 
 * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
 * https://github.com/dsprenkels/randombytes
 * https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
 */
SECTION_CODE void bcrypt_generate_iv(char *iv)
{
    HANNIBAL_INSTANCE_PTR

    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlgorithm;

    status = hannibal_instance_ptr->Win32.BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return;
    }

    status = hannibal_instance_ptr->Win32.BCryptGenRandom(hAlgorithm, iv, IV_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return;
    }

    hannibal_instance_ptr->Win32.BCryptCloseAlgorithmProvider(hAlgorithm, 0);

}

