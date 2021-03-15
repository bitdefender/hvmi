/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixagent.h"
#include "guests.h"

#include "linux/exec/exec_content.h"
#include "linux/deploy/deploy_content.h"
#include "linux/run/run_content.h"
#include "linux/init/init_content.h"
#include "linux/uninit/uninit_content.h"

//
// Init
//
LIX_AGENT_INIT_ARGS gLixAgentArgsInit =
{
    .Allocate =
    {
        .ModuleLength  = PAGE_SIZE * 3,
        .PerCpuLength  = 0x0,
    },
};

LIX_AGENT_FUNCTIONS gLixAgentFunctionsInit[] =
{
    {
        .Version =
        {
            .Sublevel   = WORD_MAX,
            .Patch      = BYTE_MAX,
            .Backport   = WORD_MAX,
            .Version    = BYTE_MAX
        },

        .Count = 3,
        .List =
        {
            { .Required = 1, .Count = 1, .Name = { "module_alloc"} },
            { .Required = 1, .Count = 1, .Name = { "change_page_attr_set_clr"} },
            { .Required = 1, .Count = 1, .Name = { "vmalloc"} },
        }
    }
};


//
// Uninit
//
LIX_AGENT_UNINIT_ARGS gLixAgentArgsUninit =
{
    .Free =
    {
        .ModuleAddress = 0x0,
        .PerCpuAddress = 0x0,
    }
};

LIX_AGENT_FUNCTIONS gLixAgentFunctionsUninit[] =
{
    {
        .Version =
        {
            .Sublevel   = WORD_MAX,
            .Patch      = BYTE_MAX,
            .Backport   = WORD_MAX,
            .Version    = BYTE_MAX
        },

        .Count = 2,
        .List =
        {
            { .Required = 1, .Count = 1, .Name = { "vfree"} },
            { .Required = 1, .Count = 1, .Name = { "change_page_attr_set_clr"} },
        }
    }
};


//
// Create thread
//
LIX_AGENT_CREATE_THREAD_ARGS gLixAgentArgsCreateThread =
{
    .Allocate =
    {
        .Length = 2 * PAGE_SIZE,
    }
};


LIX_AGENT_FUNCTIONS gLixAgentFunctionsCreateTread[] =
{
    {
        .Version =
        {
            .Sublevel   = WORD_MAX,
            .Patch      = BYTE_MAX,
            .Backport   = WORD_MAX,
            .Version    = BYTE_MAX
        },

        .Count = 3,
        .List =
        {
            { .Required = 1, .Count = 1, .Name = { "kthread_create_on_node"} },
            { .Required = 1, .Count = 1, .Name = { "wake_up_process"} },
            { .Required = 1, .Count = 2, .Name = { "vmalloc_exec", "__vmalloc_node_range" } },
        }
    }
};



//
// Deploy file
//
LIX_AGENT_THREAD_DEPLOY_FILE_ARGS gLixAgentThreadArgsDeployFile =
{
    .Allocate =
    {
        .Length = PAGE_SIZE_2M
    },

    .FilePath =
    {
        .Root = '/',
        .Name = { 0 }
    }
};


LIX_AGENT_FUNCTIONS gLixAgentFunctionsDeployFile[] =
{
    {
        .Version =
        {
            .Sublevel   = WORD_MAX,
            .Patch      = BYTE_MAX,
            .Backport   = WORD_MAX,
            .Version    = BYTE_MAX
        },

        .Count = 11,
        .List =
        {
            { .Required = 1, .Count = 1, .Name = { "filp_open"} },
            { .Required = 1, .Count = 1, .Name = { "filp_close"} },
            { .Required = 1, .Count = 2, .Name = { "kernel_write", "__kernel_write"} },
            { .Required = 1, .Count = 1, .Name = { "vmalloc" } },
            { .Required = 1, .Count = 1, .Name = { "vfree" } },
            { .Required = 1, .Count = 1, .Name = { "argv_split" } },
            { .Required = 1, .Count = 1, .Name = { "argv_free" } },
            { .Required = 1, .Count = 1, .Name = { "call_usermodehelper_setup" } },
            { .Required = 1, .Count = 1, .Name = { "call_usermodehelper_exec" } },
            { .Required = 1, .Count = 1, .Name = { "do_exit" } },
            { .Required = 1, .Count = 1, .Name = { "printk" } },
        }
    }
};


//
// Deploy file and execute
//
LIX_AGENT_THREAD_DEPLOY_FILE_EXEC_ARGS gLixAgentArgsDeployFileExec =
{
    .Allocate =
    {
        .Length = PAGE_SIZE_2M
    },

    .FilePath =
    {
        .Root = '/',
        .Name = { 0 }
    },

    .Exec =
    {
        .Args = { 0x0 }
    },
};


LIX_AGENT_THREAD_RUN_CLI_ARGS gLixAgentArgsRunCommand =
{
    .Exec =
    {
        .Args = { 0x0 }
    },
};


LIX_AGENT_FUNCTIONS gLixAgentFunctionsDeployFileExec[] =
{
    {
        .Version =
        {
            .Sublevel   = WORD_MAX,
            .Patch      = BYTE_MAX,
            .Backport   = WORD_MAX,
            .Version    = BYTE_MAX
        },

        .Count = 13,
        .List =
        {
            { .Required = 1, .Count = 1, .Name = { "filp_open"} },
            { .Required = 1, .Count = 1, .Name = { "filp_close"} },
            { .Required = 0, .Count = 1, .Name = { "flush_delayed_fput"} },
            { .Required = 1, .Count = 2, .Name = { "kernel_write", "__kernel_write"} },
            { .Required = 1, .Count = 1, .Name = { "vmalloc" } },
            { .Required = 1, .Count = 1, .Name = { "vfree" } },
            { .Required = 1, .Count = 1, .Name = { "call_usermodehelper_setup" } },
            { .Required = 1, .Count = 1, .Name = { "call_usermodehelper_exec" } },
            { .Required = 1, .Count = 1, .Name = { "argv_split" } },
            { .Required = 1, .Count = 1, .Name = { "argv_free" } },
            { .Required = 1, .Count = 1, .Name = { "do_exit" } },
            { .Required = 0, .Count = 1, .Name = { "chmod_common" } },
            { .Required = 1, .Count = 1, .Name = { "printk" } },
        }
    }
};


LIX_AGENT_FUNCTIONS gLixAgentFunctionsRunCommand[] =
{
    {
        .Version =
        {
            .Sublevel   = WORD_MAX,
            .Patch      = BYTE_MAX,
            .Backport   = WORD_MAX,
            .Version    = BYTE_MAX
        },

        .Count = 7,
        .List =
        {
            { .Required = 1, .Count = 1, .Name = { "call_usermodehelper_setup" } },
            { .Required = 1, .Count = 1, .Name = { "call_usermodehelper_exec" } },
            { .Required = 1, .Count = 1, .Name = { "argv_split" } },
            { .Required = 1, .Count = 1, .Name = { "argv_free" } },
            { .Required = 1, .Count = 1, .Name = { "do_exit" } },
            { .Required = 1, .Count = 1, .Name = { "vfree" } },
            { .Required = 1, .Count = 1, .Name = { "printk" } },
        }
    }
};


//
// Linux agent-thread handlers
//
LIX_AGENT_HANDLER gLixAgentThreadHandlers[] =
{
    {
        .Tag            = lixAgThreadTagDeployFile,
        .HypercallType  = lixAgentHypercallInt3,

        .Functions      =
        {
            .Count   = ARRAYSIZE(gLixAgentFunctionsDeployFile),
            .Content = gLixAgentFunctionsDeployFile
        },

        .Args           =
        {
            .Length = sizeof(gLixAgentThreadArgsDeployFile),
            .Content = &gLixAgentThreadArgsDeployFile
        },

        .Code           =
        {
            .Length = sizeof(gLixAgentDeploy),
            .Content = gLixAgentDeploy
        },
    },

    {
        .Tag            = lixAgThreadTagDeployFileExec,
        .HypercallType  = lixAgentHypercallInt3,

        .Functions      =
        {
            .Count   = ARRAYSIZE(gLixAgentFunctionsDeployFileExec),
            .Content = gLixAgentFunctionsDeployFileExec
        },

        .Args =
        {
            .Length = sizeof(gLixAgentArgsDeployFileExec),
            .Content = &gLixAgentArgsDeployFileExec
        },

        .Code =
        {
            .Length = sizeof(gLixAgentExec),
            .Content = gLixAgentExec
        },
    },

    {
        .Tag            = lixAgThreadTagRunCommand,
        .HypercallType  = lixAgentHypercallInt3,

        .Functions      =
        {
            .Count   = ARRAYSIZE(gLixAgentFunctionsRunCommand),
            .Content = gLixAgentFunctionsRunCommand
        },

        .Args =
        {
            .Length = sizeof(gLixAgentArgsRunCommand),
            .Content = &gLixAgentArgsRunCommand
        },

        .Code =
        {
            .Length = sizeof(gLixAgentRun),
            .Content = gLixAgentRun
        },
    }
};


//
// Linux agent handlers
//
LIX_AGENT_HANDLER gLixAgentHandler[] =
{
    {
        .Tag            = lixAgTagInit,
        .HypercallType  = lixAgentHypercallInt3,

        .Functions      =
        {
            .Count   = ARRAYSIZE(gLixAgentFunctionsInit),
            .Content = gLixAgentFunctionsInit
        },

        .Args           =
        {
            .Length  = sizeof(gLixAgentArgsInit),
            .Content = &gLixAgentArgsInit
        },

        .Code           =
        {
            .Length  = sizeof(gLixAgentInit),
            .Content = gLixAgentInit
        }
    },

    {
        .Tag            = lixAgTagUninit,
        .HypercallType  = lixAgentHypercallInt3,

        .Functions      =
        {
            .Count   = ARRAYSIZE(gLixAgentFunctionsUninit),
            .Content = gLixAgentFunctionsUninit
        },

        .Args           =
        {
            .Length  = sizeof(gLixAgentArgsUninit),
            .Content = &gLixAgentArgsUninit
        },

        .Code           =
        {
            .Length  = sizeof(gLixAgentUninit),
            .Content = gLixAgentUninit
        }
    },

    {
        .Tag            = lixAgTagCreateThread,
        .HypercallType  = lixAgentHypercallInt3,

        .Functions      =
        {
            .Count   = ARRAYSIZE(gLixAgentFunctionsCreateTread),
            .Content = gLixAgentFunctionsCreateTread
        },

        .Args           =
        {
            .Length  = sizeof(gLixAgentArgsCreateThread),
            .Content = &gLixAgentArgsCreateThread
        },

        .Threads        =
        {
            .Count   = ARRAYSIZE(gLixAgentThreadHandlers),
            .Content = gLixAgentThreadHandlers
        }
    }
};



LIX_AGENT_HANDLER *
IntLixAgentGetHandlerByTag(
    _In_ LIX_AGENT_TAG AgentTag
    )
///
/// @brief Iterates through all agent handlers and search the entry that has the provided tag.
///
/// @param[in]  AgentTag    The agent tag.
///
/// @retval     On success, returns the found handler, otherwise returns NULL.
///
{
    for (DWORD index = 0; index < ARRAYSIZE(gLixAgentHandler); index++)
    {
        if (gLixAgentHandler[index].Tag == AgentTag)
        {
            return &gLixAgentHandler[index];
        }
    }

    return NULL;
}


LIX_AGENT_HANDLER *
IntLixAgentThreadGetHandlerByTag(
    _In_ LIX_AGENT_TAG AgentTag,
    _In_ LIX_AGENT_TAG ThreadTag
    )
///
/// @brief Iterates through all thread-agent handlers and search the entry that has the provided tag.
///
/// @param[in]  AgentTag        The agent tag.
/// @param[in]  ThreadTag       The thread-agent tag.
///
/// @retval     On success, returns the found handler, otherwise returns NULL.
///
{
    LIX_AGENT_HANDLER *pHandler = NULL;

    pHandler = IntLixAgentGetHandlerByTag(AgentTag);
    if (pHandler == NULL)
    {
        return NULL;
    }

    if (pHandler->Threads.Content == NULL)
    {
        return NULL;
    }

    for (DWORD index = 0; index < pHandler->Threads.Count; index++)
    {
        if (pHandler->Threads.Content[index].Tag == ThreadTag)
        {
            return &pHandler->Threads.Content[index];
        }
    }

    return NULL;
}


