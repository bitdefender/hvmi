/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _RBTREE_H_
#define _RBTREE_H_

#include "introdefs.h"

//
// The red-black tree is a self organizing binary search tree;
// Wikipedia description: http://en.wikipedia.org/wiki/Red%E2%80%93black_tree
// The implementation is based on the "Introduction to algorithms 3rd Ed."
//

#define RBTREE_MAXIMUM_LEVEL 40

//
// RbNodeColor - Color of a node can be or RED or BLACK
//
typedef enum _RbNodeColor
{
    ncBlack = 0,
    ncRed = 1,
} RbNodeColor;

//
// RBNODE - Node representation in a Red-Black Tree;
//          Every node beside it's child nodes must have a color;
//      Properties:
//          Every RED node must have two black nodes, the leafs are black
//          Every path in the graph must contain the same number of black nodes
//
typedef struct _RBNODE
{
    struct _RBNODE *Left;
    struct _RBNODE *Right;
    struct _RBNODE *Parent;
    RbNodeColor Color;
} RBNODE, *PRBNODE;

//
// The free function must release the memory of a node with the same tag
// as it was allocated in the allocator
//
typedef void
FUNC_RbTreeNodeFree(RBNODE *Node);
typedef FUNC_RbTreeNodeFree *PFUNC_RbTreeNodeFree;


//
// Compare function - compares the keys of the nodes;
// Return values:
//      -1 - left.key < right.key
//       0 - left.key = right.key
//       1 - left.key > right.key
//
typedef int
FUNC_RbTreeNodeCompare(RBNODE *Left, RBNODE *Right);
typedef FUNC_RbTreeNodeCompare *PFUNC_RbTreeNodeCompare;

//
// Custom compare function - compares a node with a value
// Return values:
//      -1 - left.key < right.key
//       0 - left.key = right.key
//       1 - left.key > right.key
//
typedef int
FUNC_RbTreeNodeCustomCompare(RBNODE *Node, void *Key);
typedef FUNC_RbTreeNodeCustomCompare *PFUNC_RbTreeNodeCustomCompare;


//
// Tree walk callback, the callback can stop the tree walk returning a FALSE
//
typedef BOOLEAN
FUNC_RbTreeWalkCallback(RBNODE *Node, void *WalkContext);
typedef FUNC_RbTreeWalkCallback *PFUNC_RbTreeWalkCallback;

//
// RBTREE - represents a Red-Black tree, it holds the root of the tree
//
typedef struct _RBTREE
{
    RBNODE                  *Root;          // The node what represents the root of the tree
    RBNODE                  Nil;            // Nil sentinel node; the pointers in it can be arbitrary
    PFUNC_RbTreeNodeFree    NodeFree;       // The function which is used for cleanup
    PFUNC_RbTreeNodeCompare NodeCompare;    // The compare function
    volatile INT32          NodeCount;
} RBTREE, *PBTREE;


void
RbPreinit(
    _Inout_ RBTREE *Tree
    );

INTSTATUS
RbInit(
    _Inout_ RBTREE *Tree,
    _In_ PFUNC_RbTreeNodeFree NodeFree,
    _In_ PFUNC_RbTreeNodeCompare NodeCompare
    );

void
RbUninit(
    _Inout_ RBTREE *Tree
    );

INTSTATUS
RbInsertNode(
    _Inout_ RBTREE *Tree,
    _Inout_ RBNODE *Node
    );

INTSTATUS
RbLookupNode(
    _In_ RBTREE *Tree,
    _In_ RBNODE *NodeToSearch,
    _Outptr_ RBNODE **NodeFound
    );

INTSTATUS
RbLookupNodeCustomCompare(
    _In_ RBTREE *Tree,
    _In_ PFUNC_RbTreeNodeCustomCompare CompareFunc,
    _In_ void *Key,
    _Out_ RBNODE **NodeFound
    );

void
RbDeleteNode(
    _Inout_ RBTREE *Tree,
    _In_ RBNODE *Node
    );

INTSTATUS
RbWalkInorderTree(
    _In_ RBTREE *Tree,
    _In_ PFUNC_RbTreeWalkCallback Callback,
    _In_opt_ void *WalkContext
    );

#endif//_RBTREE_H_
