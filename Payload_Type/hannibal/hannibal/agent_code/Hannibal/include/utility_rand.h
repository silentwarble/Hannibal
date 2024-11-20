#ifndef UTILITY_RAND_H
#define UTILITY_RAND_H

#include "hannibal.h"

ULONG pic_rand_number_32(
    VOID
);

ULONG gen_random_byte(ULONG *seed);

#endif // UTILITY_RAND_H