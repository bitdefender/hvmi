/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTRO_LISTS_H_
#define _INTRO_LISTS_H_

#include "introtypes.h"

//
// Exported convenient versions.
// These could be a lot easier if MSVC supported typeof(), but each file could define
// a generic macro around them (see lixprocess.c)
//

typedef struct _LIST_ENTRY
{
    union
    {
        struct _LIST_ENTRY *Flink;
        struct _LIST_ENTRY *Head;
    };
    union
    {
        struct _LIST_ENTRY *Blink;
        struct _LIST_ENTRY *Tail;
    };
} LIST_ENTRY, LIST_HEAD, *PLIST_ENTRY, *PLIST_HEAD;

#ifdef INT_COMPILER_MSVC
# define OFFSET_OF(Type, Member)        ((size_t) &((Type *)0)->Member)
#else
# define OFFSET_OF(Type, Member)        __builtin_offsetof(Type, Member)
#endif // INT_COMPILER_MSVC

#define CONTAINING_RECORD(List, Type, Member)  (Type *)((size_t)(List) - OFFSET_OF(Type, Member))

// Our list implementation requires { } around name too, since that is an union
#define LIST_HEAD_INIT(Name) { { .Head = &(Name) }, { .Tail = &(Name) } }

#define list_for_each(_head, _struct_type, _var)                _list_for_each(_head, _struct_type, Link, _var)
#define list_for_next(_start, _head, _type, _var)               _list_for_next(_start, _head, _type, Link, _var)
#define list_for_each_link(_head, _struct_type, _member, _var)  _list_for_each(_head, _struct_type, _member, _var)

//
// RAW versions, use only if really needed
//
#define _next(_var, _member)                    _var->_member.Flink
#define _next_entry(_var, _member, _type)       CONTAINING_RECORD(_next(_var, _member), _type, _member)

#define PREPROC_CONCAT(a, b)            PREPROC_CONCAT_1(a, b)
#define PREPROC_CONCAT_1(a, b)          PREPROC_CONCAT_2(~, a ## b)
#define PREPROC_CONCAT_2(p, res)        res

#define UNIQUE_NAME(base)               PREPROC_CONCAT(base, __LINE__)

#define _list_for_each(_head, _type, _member, _var)                     \
    for (_type *_var = CONTAINING_RECORD(_head.Flink, _type, _member), *UNIQUE_NAME(_n) = _next_entry(_var, _member, _type); \
         &_var->_member != &_head;                                      \
         _var = UNIQUE_NAME(_n), UNIQUE_NAME(_n) = _next_entry(_var, _member, _type))

#define _list_for_next(_start, _head, _type, _member, _var)             \
    for (_type *_var = _next_entry(_start, _member, _type), *UNIQUE_NAME(_n) = _next_entry(_var, _member, _type); \
         &_var->_member != &_head;                                      \
         _var = UNIQUE_NAME(_n), UNIQUE_NAME(_n) = _next_entry(_var, _member, _type))


static inline void
InitializeListHead(
    LIST_ENTRY *ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}


static inline BOOLEAN
IsListEmpty(
    const LIST_ENTRY *ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}


static inline BOOLEAN
RemoveEntryList(
    LIST_ENTRY *Entry
    )
{
    LIST_ENTRY *blink = Entry->Blink;
    LIST_ENTRY *flink = Entry->Flink;

    blink->Flink = flink;
    flink->Blink = blink;

    Entry->Flink = NULL;
    Entry->Blink = NULL;

    return (BOOLEAN)(flink == blink);
}


static inline LIST_ENTRY *
RemoveHeadList(
    LIST_ENTRY *ListHead
    )
{
    LIST_ENTRY *entry = ListHead->Flink;
    LIST_ENTRY *flink = entry->Flink;

    ListHead->Flink = flink;
    flink->Blink = ListHead;

    return entry;
}


static inline LIST_ENTRY *
RemoveTailList(
    LIST_ENTRY *ListHead
    )
{
    LIST_ENTRY *entry = ListHead->Blink;
    LIST_ENTRY *blink = entry->Blink;

    ListHead->Blink = blink;
    blink->Flink = ListHead;

    return entry;
}


static inline void
InsertTailList(
    LIST_ENTRY *ListHead,
    LIST_ENTRY *Entry
    )
{
    LIST_ENTRY *blink = ListHead->Blink;

    Entry->Flink = ListHead;
    Entry->Blink = blink;

    blink->Flink = Entry;

    ListHead->Blink = Entry;
}


static inline void
InsertHeadList(
    LIST_ENTRY *ListHead,
    LIST_ENTRY *Entry
    )
{
    LIST_ENTRY *Flink = ListHead->Flink;

    Entry->Flink = Flink;
    Entry->Blink = ListHead;

    Flink->Blink = Entry;

    ListHead->Flink = Entry;
}


static inline void
InsertAfterList(
    LIST_ENTRY *Pivot,
    LIST_ENTRY *Item
    )
{
    Pivot->Flink->Blink = Item;
    Item->Flink = Pivot->Flink;
    Pivot->Flink = Item;
    Item->Blink = Pivot;
}


#endif // _INTRO_LISTS_H_
