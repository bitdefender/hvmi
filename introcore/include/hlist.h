/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HLIST_H_
#define _HLIST_H_

//////////////////////////////////////////////////
// NOT sufficiently tested, use at your own risk //
//////////////////////////////////////////////////

#include "introdefs.h"


typedef struct _HLIST_ENTRY
{
    struct _HLIST_ENTRY *Next;
    struct _HLIST_ENTRY **PPrev;
} HLIST_ENTRY;


typedef struct _HLIST_HEAD
{
    HLIST_ENTRY *First;
} HLIST_HEAD;


static inline void
HlistInitalizeHead(HLIST_HEAD *Head)
{
    Head->First = NULL;
}


static inline BOOLEAN
HListIsEmpty(const HLIST_HEAD *Head)
{
    return !Head->First;
}


static inline void
HListRemoveEntry(HLIST_ENTRY *Entry)
{
    HLIST_ENTRY *next = Entry->Next;
    HLIST_ENTRY **pprev = Entry->PPrev;

    *pprev = next;
    if (next)
    {
        next->PPrev = pprev;
    }
}


static inline void
HListInsert(HLIST_HEAD *Head, HLIST_ENTRY *Entry)
{
    HLIST_ENTRY *first = Head->First;
    Entry->Next = first;

    if (first)
    {
        first->PPrev = &Entry->Next;
    }

    Head->First = Entry;
    Entry->PPrev = &Head->First;
}


//
// Exported convenient versions.
// These could be a lot easier if MSVC supported typeof(), but each file could define
// a generic macro around them (see lixprocess.c)
//

#define HLIST_HEAD_INIT         { .First = NULL }

#define hlist_for_each(_head, _struct_type, _var)       _hlist_for_each(_head, _struct_type, Link, _var)
#define hlist_for_each_var(_head, _struct_type, _var)   _hlist_for_each_var(_head, _struct_type, Link, _var)

#define hlist_for_each_link(_head, _struct_type, _member, _var)     _hlist_for_each(_head, _struct_type, _member, _var)
#define hlist_for_each_link_var(_head, _struct_type, _member, _var) _hlist_for_each_var(_head, _struct_type, _member, _var)

// Doesn't make sense to have a "var" version for these (you want to remove elements after all)
#define hlist_for_each_safe(_head, _struct_type, _var)                  _hlist_for_each_safe(_head, _struct_type, Link, _var)
#define hlist_for_each_link_safe(_head, _struct_type, _member, _var)    _hlist_for_each_safe(_head, _struct_type, _member, _var)


//
// RAW versions, use only if really needed
//
#define _next_h(_var, _member)                  _var->_member.Next
#define _next_hentry(_var, _member, _type)      _var ? CONTAINING_RECORD(_next_h(_var, _member), _type, _member) : _var

#define _hlist_for_each(_head, _type, _member, _var)                    \
    for (_type *_var = CONTAINING_RECORD((_head).First, _type, _member); \
         _var;                                                          \
         _var = _next_hentry(_var, _member, _type))

#define _hlist_for_each_var(_head, _type, _member, _var)                \
    for (_var = CONTAINING_RECORD((_head).First, _type, _member);       \
         _var;                                                          \
         _var = _next_hentry(_var, _member, _type))

// Can remove entry while parsing the list
#define _hlist_for_each_safe(_head, _type, _member, _var)               \
    for (_type *_var = CONTAINING_RECORD((_head).First, _type, _member), *_n = _next_hentry(_var, _member, _type); \
         _var;                                                          \
         _var = _n, _n = _next_hentry(_var, _member, _type))

#endif // _HLIST_H_
