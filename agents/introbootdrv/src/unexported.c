#include "unexported.h"
#include "hypercall.h"

IREM_DRV_UEXFN gUnexported;

NTSTATUS
UexFindFunctions(
    void
    )
{
    for (SIZE_T i = 0; i < sizeof(gUnexported) / sizeof(void *); i++)
    {
        gUnexported._Funcs[i] = (void *)Hypercall(0, (PBYTE)i, AGENT_HCALL_SYS_LNK);
        if (NULL == gUnexported._Funcs[i])
        {
            return STATUS_NOT_FOUND;
        }
    }

    return STATUS_SUCCESS;
}

