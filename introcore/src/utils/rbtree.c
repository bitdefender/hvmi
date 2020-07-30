/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcrt.h"

#define RB_NODE_IS_BLACK(Node) (ncBlack == (Node)->Color)
#define RB_NODE_IS_RED(Node) (ncRed == (Node)->Color)


static void
RbpLeftRotate(
    _Inout_ RBTREE *Tree,
    _Inout_ RBNODE *Node
    )
{
    // Algorithm:
    // ==========
    // LEFT-ROTATE(T, x)
    // 1  y = x.right      // set y
    // 2  x.right = y.left // turn y's left subtree into x's right subtree
    // 3  if y.left != T.nil
    // 4    y.left.p = x
    // 5  y.p = x.p        // link x's parent to y
    // 6  if x.p == T.nil
    // 7    T.root = y
    // 8  elseif x == x.p.left
    // 9    x.p.left = y
    // 10 else x.p.right = y
    // 11 y.left = x       // put x on y's left
    // 12 x.p = y

    RBNODE *x = Node;
    RBNODE *y = x->Right;                   // #1
    x->Right = y->Left;                     // #2

    if (&Tree->Nil != y->Left)              // #3
    {
        y->Left->Parent = x;                // #4
    }

    y->Parent = x->Parent;                  // #5

    if (&Tree->Nil == x->Parent)            // #6
    {
        Tree->Root = y;                     // #7
    }
    else if (x == x->Parent->Left)          // #8
    {
        x->Parent->Left = y;                // #9
    }
    else
    {
        x->Parent->Right = y;               // #10
    }

    y->Left = x;                            // #11
    x->Parent = y;                          // #12
}


static void
RbpRightRotate(
    _Inout_ RBTREE *Tree,
    _Inout_ RBNODE *Node
    )
{
    // Algorithm:
    // ==========
    // RIGHT-ROTATE(T, x)
    // 1  y = x.left      // set y
    // 2  x.left = y.right// turn y's right subtree into x's left subtree
    // 3  if y.right != T.nil
    // 4    y.right.p = x
    // 5  y.p = x.p        // link x's parent to y
    // 6  if x.p == T.nil
    // 7    T.root = y
    // 8  elseif x == x.p.right
    // 9    x.p.right = y
    // 10 else x.p.left = y
    // 11 y.right = x       // put x on y's right
    // 12 x.p = y

    RBNODE *x = Node;
    RBNODE *y = x->Left;                    // #1
    x->Left = y->Right;                     // #2

    if (&Tree->Nil != y->Right)             // #3
    {
        y->Right->Parent = x;               // #4
    }

    y->Parent = x->Parent;                  // #5

    if (&Tree->Nil == x->Parent)            // #6
    {
        Tree->Root = y;                     // #7
    }
    else if (x == x->Parent->Right)         // #8
    {
        x->Parent->Right = y;               // #9
    }
    else
    {
        x->Parent->Left = y;                // #10
    }

    y->Right = x;                           // #11
    x->Parent = y;                          // #12
}


static void
RbpDeleteFixup(
    _Inout_ RBTREE *Tree,
    _In_ RBNODE *Node
    )
{
    // Algorithm:
    // ==========
    // RB-DELETE-FIXUP (T, x)
    // 1  while x != T.root and x.color == BLACK
    // 2    if x == x.p.left
    // 3      w = x.p.right
    // 4      if w.color == RED
    // 5        w.color = BLACK        // case 1
    // 6        x.p.color = RED        // case 1
    // 7        LEFT-ROTATE(T, x.p)    // case 1
    // 8        w = x.p.right          // case 1
    // 9      if w.left.color == BLACK and w.right.color == BLACK
    // 10       w.color = RED          // case 2
    // 11       x = x.p                // case 2
    // 12     else if w.right.color == BLACK
    // 13         w.left.color = BLACK // case 3
    // 14         w.color = RED        // case 3
    // 15         RIGHT-ROTATE(T, w)   // case 3
    // 16         w = x.p.right        // case 3
    // 17       w.color = x.p.color    // case 4
    // 18       x.p.color = BLACK      // case 4
    // 19       w.right.color = BLACK  // case 4
    // 20       LEFT-ROTATE(T, x.p)    // case 4
    // 21       x = T.root             // case 4
    // 22   else
    // 23     w = x.p.left
    // 24     if w.color == RED
    // 25       w.color = BLACK        // case 1
    // 26       x.p.color = RED        // case 1
    // 27       RIGHT-ROTATE(T, x.p)   // case 1
    // 28       w = x.p.left           // case 1
    // 29     if w.right.color == BLACK and w.left.color == BLACK
    // 30       w.color = RED          // case 2
    // 31       x = x.p                // case 2
    // 32     else if w.left.color == BLACK
    // 33         w.right.color = BLACK // case 3
    // 34         w.color = RED        // case 3
    // 35         LEFT-ROTATE(T, w)    // case 3
    // 36         w = x.p.left         // case 3
    // 37       w.color = x.p.color    // case 4
    // 38       x.p.color = BLACK      // case 4
    // 39       w.left.color = BLACK   // case 4
    // 40       RIGHT-ROTATE(T, x.p)    // case 4
    // 41       x = T.root             // case 4
    // 42 x.color = BLACK

    RBNODE *x = Node;
    RBNODE *w = &Tree->Nil;

    while (x != Tree->Root && x->Color == ncBlack)                      // #1
    {
        if (x == x->Parent->Left)                                       // #2
        {
            w = x->Parent->Right;                                       // #3

            if (RB_NODE_IS_RED(w))                                      // #4
            {
                w->Color = ncBlack;                                     // #5
                x->Parent->Color = ncRed;                               // #6
                RbpLeftRotate(Tree, x->Parent);                         // #7
                w = x->Parent->Right;                                   // #8
            }

            if (RB_NODE_IS_BLACK(w->Left) && RB_NODE_IS_BLACK(w->Right))// #9
            {
                w->Color = ncRed;                                       // #10
                x = x->Parent;                                          // #11
            }
            else
            {
                if (RB_NODE_IS_BLACK(w->Right))                         // #12
                {
                    w->Left->Color = ncBlack;                           // #13
                    w->Color = ncRed;                                   // #14
                    RbpRightRotate(Tree, w);                            // #15
                    w = x->Parent->Right;                               // #16
                }

                w->Color = x->Parent->Color;                            // #17
                x->Parent->Color = ncBlack;                             // #18
                w->Right->Color = ncBlack;                              // #19
                RbpLeftRotate(Tree, x->Parent);                         // #20
                x = Tree->Root;                                         // #21
            }
        }
        else                                                            // #22
        {
            w = x->Parent->Left;                                        // #3

            if (RB_NODE_IS_RED(w))                                      // #4
            {
                w->Color = ncBlack;                                     // #5
                x->Parent->Color = ncRed;                               // #6
                RbpRightRotate(Tree, x->Parent);                        // #7
                w = x->Parent->Left;                                    // #8
            }

            if (RB_NODE_IS_BLACK(w->Right) && RB_NODE_IS_BLACK(w->Left))// #9
            {
                w->Color = ncRed;                                       // #10
                x = x->Parent;                                          // #11
            }
            else
            {
                if (RB_NODE_IS_BLACK(w->Left))                          // #12
                {
                    w->Right->Color = ncBlack;                          // #13
                    w->Color = ncRed;                                   // #14
                    RbpLeftRotate(Tree, w);                             // #15
                    w = x->Parent->Left;                                // #16
                }

                w->Color = x->Parent->Color;                            // #17
                x->Parent->Color = ncBlack;                             // #18
                w->Left->Color = ncBlack;                               // #19
                RbpRightRotate(Tree, x->Parent);                        // #20
                x = Tree->Root;                                         // #21
            }
        }
    }

    x->Color = ncBlack;
}


static void
RbpInsertFixup(
    _Inout_ RBTREE *Tree,
    _Inout_ RBNODE *Node
    )
{
    // Algorithm:
    // ==========
    // RB-INSERT-FIXUP(T, z)
    // 1 while z.p:color == RED
    // 2   if z.p == z.p.p.left
    // 3     y = z.p.p.right
    // 4     if y.color == RED
    // 5       z.p.color = BLACK         // case 1
    // 6       y.color = BLACK           // case 1
    // 7       z.p.p.color = RED         // case 1
    // 8       z = z.p.p                 // case 1
    // 9     else if z == z.p.right
    // 10        z = z.p                 // case 2
    // 11        LEFT-ROTATE(T, z)       // case 2
    // 12      z.p.color = BLACK         // case 3
    // 13      z.p.p.color = RED         // case 3
    // 14      RIGHT-ROTATE(T, z.p.p)    // case 3
    // 15  else
    // 16    y = z.p.p.left
    // 17    if y.color == RED
    // 18      z.p.color = BLACK         // case 4
    // 19      y.color = BLACK           // case 4
    // 20      z.p.p.color = RED         // case 4
    // 21      z = z.p.p                 // case 4
    // 22    else if z == z.p.left
    // 23        z = z.p                 // case 5
    // 24        RIGHT-ROTATE(T, z)      // case 5
    // 25      z.p.color = BLACK         // case 6
    // 26      z.p.p.color = RED         // case 6
    // 27      LEFT-ROTATE(T, z.p.p)     // case 6
    // 28 T.root.color = BLACK

    RBNODE *z = Node;
    RBNODE *y = &Tree->Nil;

    while (RB_NODE_IS_RED(z->Parent))               // #1
    {
        if (z->Parent == z->Parent->Parent->Left)   // #2
        {
            y = z->Parent->Parent->Right;           // #3

            if (RB_NODE_IS_RED(y))                  // #4
            {
                z->Parent->Color = ncBlack;         // #5
                y->Color = ncBlack;                 // #6
                z->Parent->Parent->Color = ncRed;   // #7
                z = z->Parent->Parent;              // #8
            }
            else
            {
                if (z == z->Parent->Right)          // #9
                {
                    z = z->Parent;                  // #10
                    RbpLeftRotate(Tree, z);          // #11
                }
                z->Parent->Color = ncBlack;         // #12
                z->Parent->Parent->Color = ncRed;   // #13
                RbpRightRotate(Tree, z->Parent->Parent); // #14
            }
        }
        else                                        // #15
        {
            y = z->Parent->Parent->Left;            // #16

            if (RB_NODE_IS_RED(y))                  // #17
            {
                z->Parent->Color = ncBlack;         // #18
                y->Color = ncBlack;                 // #19
                z->Parent->Parent->Color = ncRed;   // #20
                z = z->Parent->Parent;              // #21
            }
            else
            {
                if (z == z->Parent->Left)           // #22
                {
                    z = z->Parent;                  // #23
                    RbpRightRotate(Tree, z);         // #24
                }
                z->Parent->Color = ncBlack;         // #25
                z->Parent->Parent->Color = ncRed;   // #26
                RbpLeftRotate(Tree, z->Parent->Parent); // #27
            }
        }
    }

    Tree->Root->Color = ncBlack;                    // #28
}


static void
RbpTransplant(
    _Inout_ RBTREE *Tree,
    _In_ RBNODE *Node1,
    _In_ RBNODE *Node2
    )
{
    // Algorithm:
    // ===========
    // RB-TRANSPLANT(T, u, v)
    // 1 if u.p == T.nil
    // 2   T.root = v
    // 3 elseif u == u.p.left
    // 4   u.p.left = v
    // 5 else u.p.right = v
    // 6 v.p = u.p

    if (Node1->Parent == &Tree->Nil)
    {
        Tree->Root = Node2;
    }
    else
    {
        if (Node1 == Node1->Parent->Left)
        {
            Node1->Parent->Left = Node2;
        }
        else
        {
            Node1->Parent->Right = Node2;
        }
    }

    Node2->Parent = Node1->Parent;
}


void
RbPreinit(
    _Inout_ RBTREE *Tree
    )
{
    memzero(Tree, sizeof(*Tree));
}


INTSTATUS
RbInit(
    _Inout_ RBTREE *Tree,
    _In_ PFUNC_RbTreeNodeFree NodeFree,
    _In_ PFUNC_RbTreeNodeCompare NodeCompare
    )
{
    if (NULL == Tree)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == NodeFree)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == NodeCompare)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    Tree->Root = &Tree->Nil;
    Tree->Nil.Left = Tree->Nil.Right = Tree->Nil.Parent = &Tree->Nil;
    Tree->Nil.Color = ncBlack;
    Tree->NodeFree = NodeFree;
    Tree->NodeCompare = NodeCompare;
    Tree->NodeCount = 0;

    return INT_STATUS_SUCCESS;
}


void
RbUninit(
    _Inout_ RBTREE *Tree
    )
{
    RBNODE *stack[RBTREE_MAXIMUM_LEVEL + 1];
    int level = 0;

    stack[0] = Tree->Root;
    while (Tree->NodeCount > 1)
    {
        // if left node is not Nil
        if (&Tree->Nil != stack[level]->Left)
        {
            // traversing the left node first
            level++;
            stack[level] = stack[level - 1]->Left;
            continue;
        }

        // if right node is not nil
        if (&Tree->Nil != stack[level]->Right)
        {
            // traversing the right node
            level++;
            stack[level] = stack[level - 1]->Right;
            continue;
        }

        // if we are here, the node has no children
        // so we can delete the node deleting node

        // we can address level-1, because when nodecount is greater than 1
        // we always have a root
        if (stack[level - 1]->Left == stack[level])
        {
            // case 1: left child
            stack[level - 1]->Left = &Tree->Nil;
        }
        else
        {
            // case 2: right child
            stack[level - 1]->Right = &Tree->Nil;
        }

        Tree->NodeFree(stack[level]);
        Tree->NodeCount -= 1;
        level--;
    }

    if (Tree->Root != &Tree->Nil)
    {
        Tree->NodeFree(Tree->Root);
        Tree->NodeCount = 0;
        Tree->Root = &Tree->Nil;
    }
}


RBNODE *
RbSearch(
    _In_ RBTREE *Tree,
    _In_ RBNODE *NodeToSearch,
    _Outptr_ RBNODE **Parent
    )
{
    RBNODE *node = Tree->Root;
    *Parent = &Tree->Nil;

    while (&Tree->Nil != node)
    {
        int cmp = Tree->NodeCompare(node, NodeToSearch);

        if (0 == cmp)           // we found the node
        {
            break;
        }

        *Parent = node;         // setting the parent of the node properly
        if (0 > cmp)            // the node is lesser
        {
            node = node->Right;
            continue;
        }

        // the node is greater
        node = node->Left;
    }

    if (node == &Tree->Nil)
    {
        node = NULL;
    }

    return node;
}


INTSTATUS
RbLookupNode(
    _In_ RBTREE *Tree,
    _In_ RBNODE *NodeToSearch,
    _Outptr_ RBNODE **NodeFound
    )
{
    RBNODE *parent;

    if (NULL == Tree)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == NodeToSearch)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == NodeFound)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    *NodeFound = RbSearch(Tree, NodeToSearch, &parent);

    if (NULL == *NodeFound)
    {
        return INT_STATUS_DATA_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
RbLookupNodeCustomCompare(
    _In_ RBTREE *Tree,
    _In_ PFUNC_RbTreeNodeCustomCompare CompareFunc,
    _In_ void *Key,
    _Out_ RBNODE **NodeFound
    )
{
    RBNODE *node;

    if (NULL == Tree)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == NodeFound)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    node = Tree->Root;

    while (&Tree->Nil != node)
    {
        int cmp = CompareFunc(node, Key);

        if (0 == cmp)           // we found the node
        {
            break;
        }

        if (0 > cmp)            // the node is lesser
        {
            node = node->Right;
            continue;
        }

        // the node is greater
        node = node->Left;
    }

    if (node == &Tree->Nil)
    {
        node = NULL;
        *NodeFound = NULL;
        return INT_STATUS_DATA_NOT_FOUND;
    }

    *NodeFound = node;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
RbInsertNode(
    _Inout_ RBTREE *Tree,
    _Inout_ RBNODE *Node
    )
{
    // Algorithm:
    // ==========
    // RB-INSERT (T, z)
    // 1 y = T.nil
    // 2 x = T.root
    // 3 while x != T.nil
    // 4   y = x
    // 5   if z.key < x.key
    // 6     x = x.left
    // 7   else x = x:right
    // 8 z.p = y
    // 9 if y == T.nil
    // 10   T.root = z
    // 11 else if z.key < y.key
    // 12   y.left = z
    // 13 else y.right = z
    // 14 z.left = T.nil
    // 15 z.right = T.nil
    // 16 z.color = RED
    // 17 RB-INSERT-FIXUP(T, z)

    RBNODE *auxNode;
    RBNODE *parentNode;
    int cmp;

    if (NULL == Tree)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Node || &Tree->Nil == Node)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // searching in the tree
    // steps #1 -> #7
    // y <- parentNode
    auxNode = RbSearch(Tree, Node, &parentNode);

    ///       - If the key was found overwrite it
    if (NULL != auxNode)
    {
        // special case: cannot insert an element with the same key
        return INT_STATUS_KEY_ALREADY_EXISTS;
    }

    Tree->NodeCount++;

    Node->Parent = parentNode;                  // #8
    if (&Tree->Nil == parentNode)               // #9
    {
        // the tree was empty
        Tree->Root = Node;                      // #10
    }
    else
    {
        cmp = Tree->NodeCompare(Node, parentNode);
        if (cmp < 0)                            // #11
        {
            parentNode->Left = Node;            // #12
        }
        else
        {
            parentNode->Right = Node;           // #13
        }
    }

    Node->Left = &Tree->Nil;                    // #14
    Node->Right = &Tree->Nil;                   // #15
    Node->Color = ncRed;                        // #16

    RbpInsertFixup(Tree, Node);

    return INT_STATUS_SUCCESS;
}


RBNODE *
RbTreeMinimum(
    _In_ RBTREE *Tree,
    _In_ RBNODE *Node
    )
{
    while (Node != NULL)
    {
        if (&Tree->Nil == Node->Left)
        {
            break;
        }

        Node = Node->Left;
    }

    return Node;
}


void
RbDeleteNode(
    _Inout_ RBTREE *Tree,
    _In_ RBNODE *Node
    )
{
    //RB-DELETE(T, z)
    //1  y = z
    //2  y-original-color = y.color
    //3  if z.left == T.nil
    //4    x = z.right
    //5    RB-TRANSPLANT(T, z, z.right)
    //6  elseif z.right == T.nil
    //7    x = z.left
    //8    RB-TRANSPLANT(T, z, z.left)
    //9  else y = TREE-MINIMUM(z.right)
    //10   y-original-color = y.color
    //11   x = y.right
    //12   if y.p == z
    //13     x.p = y
    //14   else RB-TRANSPLANT(T, y, y.right)
    //15     y.right = z.right
    //16     y.right.p = y
    //17   RB-TRANSPLANT(T, z, y)
    //18   y.left = z.left
    //19   y.left.p = y
    //20   y.color = z.color
    //21 if y-original-color == BLACK
    //22   RB-DELETE-FIXUP(T, x)

    RBNODE *z = Node;
    RBNODE *y = z;                                 // #1
    RBNODE *x = &Tree->Nil;
    RbNodeColor yOrigColor = y->Color;             // #2

    if (&Tree->Nil == z->Left)
    {
        x = z->Right;
        RbpTransplant(Tree, z, z->Right);
    }
    else
    {
        if (&Tree->Nil == z->Right)
        {
            x = z->Left;
            RbpTransplant(Tree, z, z->Left);
        }
        else
        {
            y = RbTreeMinimum(Tree, z->Right);
            yOrigColor = y->Color;
            x = y->Right;

            if (y->Parent == z)
            {
                x->Parent = y;
            }
            else
            {
                RbpTransplant(Tree, y, y->Right);
                y->Right = z->Right;
                y->Right->Parent = y;
            }

            RbpTransplant(Tree, z, y);

            y->Left = z->Left;
            y->Left->Parent = y;
            y->Color = z->Color;
        }
    }

    if (yOrigColor == ncBlack)
    {
        RbpDeleteFixup(Tree, x);
    }

    Node->Parent = NULL;
    Node->Left = NULL;
    Node->Right = NULL;
    Node->Color = ncBlack;

    Tree->NodeCount--;
}


//
// We need to disable this warning on gcc/clang since the build will fail with -Werror
//
#if defined(INT_COMPILER_GNUC) || (defined(INT_UNIX) && defined(INT_COMPILER_CLANG))
_Pragma("GCC diagnostic push");
_Pragma("GCC diagnostic ignored \"-Wstrict-overflow\"")
#endif



INTSTATUS
RbWalkInorderTree(
    _In_ RBTREE *Tree,
    _In_ PFUNC_RbTreeWalkCallback Callback,
    _In_opt_ void *WalkContext
    )
{
    //
    // On the stack we will stock the current state of the node;
    // Possible values:
    //   0 - no nodes were visited
    //   1 - left node was visited - the current node should be visited
    //   2 - the current node was visited, we should go for the right node
    //   3 - all nodes were visited
    //
    size_t stack[RBTREE_MAXIMUM_LEVEL + 1];
    ssize_t level = 0;
    RBNODE *node = NULL;
    BOOLEAN res = FALSE;

    node = Tree->Root;
    stack[level] = 0;

    if (Tree->Root == &Tree->Nil)
    {
        // the tree is empty
        return INT_STATUS_SUCCESS;
    }

    while (level >= 0)
    {
        if (level == RBTREE_MAXIMUM_LEVEL)
        {
            return INT_STATUS_BUFFER_OVERFLOW;
        }

        switch (stack[level])
        {
        case 0:
            stack[level] = 1;   // we set that this node

            if (node->Left != &Tree->Nil)
            {
                // otherwise we should go for the next node in the left side
                level += 1;
                node = node->Left;  // visiting the left node
                stack[level] = 0;   // setting it's state as 0 - no left side was visited
            }

            break;

        case 1:
            // the left node was visited
            stack[level] = 2;
            res = Callback(node, WalkContext);    // calling the given function

            if (!res)
            {
                // on FALSE we should stop the walking process
                return INT_STATUS_FOUND;
            }

            break;

        case 2:
            // current node was visited, we should visit the left side node
            stack[level] = 3;

            if (node->Right != &Tree->Nil)
            {
                level += 1;
                node = node->Right;
                stack[level] = 0;
            }

            break;

        case 3:
            // the left node was visited, we should go one level up
            level -= 1;
            node = node->Parent;
            break;
        }
    }

    return INT_STATUS_SUCCESS;
}

#if defined(INT_COMPILER_GNUC) || (defined(INT_UNIX) && defined(INT_COMPILER_CLANG))
_Pragma("GCC diagnostic pop");
#endif
