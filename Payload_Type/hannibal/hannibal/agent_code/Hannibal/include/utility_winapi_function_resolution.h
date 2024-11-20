#ifndef UTILITY_WINAPI_FUNCTION_RESOLUTION_H
#define UTILITY_WINAPI_FUNCTION_RESOLUTION_H

#include "hannibal.h"


PVOID get_module_ptr_from_peb(
    _In_ ULONG Hash
);

PVOID get_func_ptr_from_module_eat(
    _In_ PVOID Module,
    _In_ ULONG Function
);

#endif // UTILITY_WINAPI_FUNCTION_RESOLUTION_H
