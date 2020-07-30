/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _QUEUE_H_
#define _QUEUE_H_

#include "introtypes.h"

typedef struct _QUEUE
{
    union
    {
        struct _QUEUE       *Next;
        struct _QUEUE       *Head;
    };
} QUEUE_ENTRY, *PQUEUE_ENTRY, QUEUE_HEAD, *PQUEUE_HEAD;


__forceinline void
QueueInitialize(
    _Out_ QUEUE_HEAD *QueueHead
    )
{
    QueueHead->Next = QueueHead;
}


__forceinline BOOLEAN
QueueIsEmpty(
    _In_ QUEUE_HEAD *QueueHead
    )
{
    return (BOOLEAN)(QueueHead->Next == QueueHead);
}


__forceinline QUEUE_ENTRY *
QueueRemove(
    _In_ QUEUE_HEAD *QueueHead
    )
{
    QUEUE_ENTRY *head = QueueHead->Head;

    QueueHead->Head = head->Next;

    return head;
}


__forceinline void
QueueInsert(
    _In_ QUEUE_HEAD *QueueHead,
    _In_ QUEUE_ENTRY *Element
    )
{
    QUEUE_ENTRY *oldHead = QueueHead->Head;
    QueueHead->Head = Element;

    Element->Next = oldHead;
}

#endif // _QUEUE_H_
