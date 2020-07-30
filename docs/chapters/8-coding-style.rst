============
Coding Style
============

The purpose of this coding style is to ensure code consistency across
different files, modules, and authors, along with tackling security and
performance issues by providing useful guidelines for how code should be
written.

The rules in this coding style apply to the Introcore sources. Auxiliary
projects that are written in languages other than C and for a specific
operating system should follow the standard coding style for that
specific operating system or language.

This guide is intended to illustrate **allowed** behavior when writing
Introcore code. Anything not listed explicitly in this guide is
**strictly forbidden**. As this guide is not intended to be final, it
can be modified under justified circumstances.

Indentation and line ending
===========================

- Code must be indented using 4 **spaces**. Most text editors and IDEs
  have settings for inserting **spaces** instead of **TAB**.
- All the files must use **Linux (LF) line endings**.
- Lines should **not be longer** than **120** characters.

Naming conventions
==================

- **All variables, constants, functions, macros, type** must have
  a **descriptive** or **mnemonic**  name.
- Usage of **hard-coded magic values is not permitted**. If needed,
  magic values must be defined, either using a **macro** or the
  :code:`const` keyword, and given a proper name.
- **Names** can be **abbreviated**, where their meaning is obvious:

  .. code-block:: c
    
    int max; // instead of maximum 

- **All names** must be expressed in **English**. 
- **Function names** and **function parameters** must be written using **PascalCase**:

  .. code-block:: c

    int                 
    Function(           
        int Parameter1, 
        int ParameterTwo
        );

- **Local variable** names must be written using **camelCase**; avoid prepending the variable type in its name:

  .. code-block:: c

    DWORD count; // instead of dwCount 

- **Global variable** names must be written using **PascalCase** and they must be prepended by the
  letter **g**:

  .. code-block:: c

    DWORD gGlobalCounter;

- **Types**, **structures**, **unions**, and **enums** must be defined
  using **ALL_CAPS**, with **underscore** separating different words in the name, if needed:

  .. code-block:: c

    typedef struct     
    {                  
        DWORD Field1;  
        DWORD Field2;  
    } CUSTOM_STRUCTURE;
                   
    typedef int MY_INT;

- **Pointer types** should be defined with a preceding capital letter **P**:

  .. code-block:: c

    typedef int *PMY_INT;

- **Structures** and **unions** fields must be named using **PascalCase**, one per line;
  an exception from the naming rule is accepted for very short names (max 3 characters), bit-fields
  and reserved fields:

  .. code-block:: c

    typedef struct     
    {                  
        DWORD Field1;  
        DWORD Field2;
        DWORD reserved;  
    } CUSTOM_STRUCTURE;

- **Enums** must have a **prefix**, indicating the type of the enum, and should be written
  using **camelCase** or **ALL_CAPS** (similar to macros); try to maintain consistency within 
  the same module/project when it comes to enums:

  .. code-block:: c

    enum           
    {              
        colRed,    
        colBlue,   
        colYellow, 
        colGreen   
    } COLORS;      

    enum           
    {              
        COL_RED,   
        COL_BLUE,  
        COL_YELLOW,
        COL_GREEN  
    } COLORS;      

- **Macros** must be defined using **ALL_CAPS**, with
  **underscore** separating different words in the name. The exception
  from this rule are **function wrappers** or **function-like macros**, 
  which can be defined using **PascalCase**; :code:`foreach`
  macros can be declared with lower case letters:

  .. code-block:: c

    #define MAX_INT(a, b) ((a) > (b) ? (a) : (b))             

    // This is allowed, as it is a function wrapper.          
    #define SomeFunctionWrapper(a, b)       SomeFunction(a, b)

- All **public types** from a module must contain at least a portion of
  the name which is specific for the module it belongs to; multiple
  such prefixes are accepted, and encouraged, to clearly identify the
  origin of that function or type; In Introcore, all functions use the
  prefix :code:`Int`. OS specific functions use the
  prefix :code:`IntWin` (for Windows) and :code:`IntLix` (for Linux).
  Addition prefixes can be added to further illustrate the origin of
  the function (for example: :code:`IntWinProcCreateObject`):

  .. code-block:: c

    // Module colors - note how every type uses the prefix col.

    #define COL_MASK        0xFFFFFFFF                         

    typedef enum _COL_COLOR                                    
    {                                                          
        colRed,                                                
        colBlue,                                               
        colYellow,                                             
        colGreen                                               
    } COL_COLOR;                                               

    typedef struct _COL_MIXTURE                                
    {                                                          
        COL_COLOR Color1;                                      
        COL_COLOR Color2;                                      
    } COL_MIXTURE;                                             

    void                                                       
    ColMixColors(                                              
        const COL_COLOR Color1,                                
        const COL_COLOR Color2,                                
        COL_MIXTURE *Mixture                                   
        );                                                     

Spacing
=======

- **Operands** within expressions **must** be separated by spaces:

  .. code-block:: c

    a = b + c * d;
    x = y & z;    
    b = c1 && c2; 
    y += w * q;   

- Spaces **must not** be placed between a variable and **pre/post increment/decrement** operators:

  .. code-block:: c

    x++;
    x--;
    --y;
    ++y;

- Spaces **must not** be placed between a variable and **unary** operators:

  .. code-block:: c

    y = -x;
    b = !c;
    d = ~e;

- **Arguments** passed to functions **must** be separated by spaces.
- Spaces **must not** be placed between the **function name** and
  the **opening parenthesis** on function calls:

  .. code-block:: c

    f(a, b, c, d);

- The **ternary operator must** contains spaces around the condition and expressions:

  .. code-block:: c

    r = x ? y : z;

- Spaces **must not** be placed before **comma** or **semicolon**:

  .. code-block:: c

    for (int i = 0; i < n; i++) ...
    int a, b, c;                   
    f(a, b, c);     

- Spaces **must not** be placed before or after **structure and union member access** operators:

  .. code-block:: c

    x = x + s1.SomeField;      
    y = y + s2->SomeOtherField;

- Spaces **must not** be placed after **address-of** or **dereference** operators:

  .. code-block:: c

    p = &a;
    q = *b;

- Spaces **must** be placed between the :code:`if`, :code:`for`, :code:`while`, 
  :code:`do`, :code:`switch` statements and the opening parenthesis:

  .. code-block:: c

    for (int i = 0; i < n; i++) ...
    if (c1 && c2) ...              
    switch (a) ...          

- Spaces **must not** be placed before the **array subscript** operator:

  .. code-block:: c

    x = array[1];

- Spaces **must not** be placed between a **type** and a
  **variable** when type-casting, and **must not** be placed before
  or after the type inside the parenthesis:

  .. code-block:: c

    x = (int)y;

- When declaring pointer type variables (or pointer type function
  arguments), the space **precedes** the asterisk character:

  .. code-block:: c

    DWORD *ptr;

Include guards and macros
=========================

- All the contents in a header file must be enclosed in a :code:`#ifndef` / 
  :code:`#define` / :code:`#endif` sequence that defines a unique macro name
  for that header file. For example, for a file names *foo.h*:

  .. code-block:: c

    #ifndef _FOO_H_   
    #define _FOO_H_   
    ...               
    #endif // !_FOO_H_


- Avoid defining macros needed only in a source file in headers - if it
  is not needed by other parts of Introcore it should not be exposed,
  and it should be defined in the source file only.
- Macros should be used either to **define constants**, for **specific expressions**, 
  or for **function wrappers**:

  .. code-block:: c

    #define PAGE_SIZE_4K 4096u                                           
    #define IS_KERNEL_POINTER_LIX(p) (((p) >= 0xFFFF800000000000) && ((p) < 0xffffffffffe00000))                                                 
    #define HpAllocWithTag(Len, Tag) calloc(1, Len)                      


- Do not use macros to define a "meta-language", avoid excessive usage,
  and try to not hide complex functionalities inside a macro, as this
  can create confusion and make the code harder to understand.
- It is **forbidden to use control-flow statements inside macros or to make macros dependent on a local variable**.
  Exceptions for this rule can be applied for 
  **locally defined macros or very specific, repetitive tasks, on a case by case basis** (for example,
  instruction emulation).
- Macros that take **arguments** must enclose the arguments inside **parentheses**:

  .. code-block:: c

    #define SIGN_EX_8(x) ((x) & 0x00000080 ? 0xFFFFFFFFFFFFFF00 | (x) : (x))

- Introcore already has a variety of useful macros available (like
  :code:`ARRAYSIZE`, :code:`PAGE_REMAINING`, etc). Do not reinvent them!

Functions
=========

- Both the **definition** and the **declaration** of a function must
  use basic `Microsoft SAL`_ annotations.
- Both the **name** and the **parameters** must use the **PascalCase**,
  as indicated in the :ref:`Naming Conventions <chapters/8-coding-style:Naming Conventions>` section.
- Public functions must be **declared** in the header file
  and **defined** in the source file.
- Inline functions can be **defined** in the header file.
- Each function parameter must be written on a separate line.
- Functions that take no parameters must be written with a :code:`void` parameter list:

  .. code-block:: c

    BOOLEAN                                        
    IntWinProcIsTokenStolen(                       
        _In_ WIN_PROCESS_OBJECT *Process,          
        _In_ BOOLEAN Check,                        
        _Out_opt_ WIN_PROCESS_OBJECT **FromProcess,
        _Out_opt_ QWORD *OldValue,                 
        _Out_opt_ QWORD *NewValue                  
        );                                         

    BOOLEAN                                        
    GlueIsVeApiAvailable(                          
        void                                       
        );                                         


- Functions that are internal to a source file must be declared :code:`static`:

  .. code-block:: c

    static void              
    IntSerializeProcess(     
        _In_ void *Process,  
        _In_ DWORD ObjectType
        );                   


- The **definition** and the **declaration** of a function must be the
  same, including the SAL annotations.
- Input-only parameters should be :code:`const`.
- Sometimes, a module contains a public function which does some
  additional validations or acquires/releases locks, and an internal
  function which does the actual job. In this case, the internal
  function should be :code:`static`, and its name should be the same as
  the public function and terminated with the :code:`Internal` suffix:

  .. code-block:: c

    static INTSTATUS              
    IntHookGpaRemoveHookInternal( 
        _In_ HOOK_GPA *Hook,      
        _In_ DWORD Flags          
        );                        

    INTSTATUS                     
    IntHookGpaRemoveHook(         
        _Inout_ HOOK_GPA **Hook,  
        _In_ DWORD Flags          
        );                        


- The declaration of a function pointers must be done using the
  following template. The :code:`PFUNC_` prefix is mandatory.

  .. code-block:: c

    typedef RETURN_TYPE 
    (*PFUNC_Name)(      
        _In_ void *Param
        );              


Local variables
===============

- **Variable shadowing** is forbidden. For example, this is not allowed:

  .. code-block:: c

    BYTE *buffer = HpAllocWithTag(size, tag);      
    if (buffer != NULL)                            
    {                                              
        BYTE *buffer = HpAllocWithTag(size2, tag2);
    }                                              

- Try to define variables in the **most reduced scope possible**:

  .. code-block:: c

    for (DWORD i = 0; ...) // instead of DWORD i; for (i = 0; ...)

- Local variables should be **defined at the beginning of the block**.

Global variables
================

- Global variables shared between multiple source files are discouraged - usually, 
  most of the needed global state is related to the
  protected guest, in which case the existing global guest state should
  be enough. If this cannot be avoided, do not declare the variables
  as :code:`extern` in the source files directly - put :code:`extern` declaration 
  in a header file that can be shared between multiple source files. 
  This makes it easier to change in the future, as well as ensuring that all users have the same definition. 
- Global variables that hold global state used only in a single source file must be declared :code:`static`, for example:

  .. code-block:: c

    static DWORD gPendingDrivers = 0;

- Global variables that are used only in a single function can have
  their scope further reduced by declaring them as :code:`static` inside
  the function that uses them. 

Defining and using structures, unions, and enums
================================================

- **Structure**, **union**, **enum names** and their **fields** are
  subject to the :ref:`Naming Conventions <chapters/8-coding-style:Naming Conventions>` section restrictions.
- **A single field per line** is accepted when defining **structures**, **unions**, and **enums**:

  .. code-block:: c

    struct             
    {                  
        DWORD   Field1;
        DWORD   Field2;
    } MY_STRUCTURE;    


- Fields inside **structures**, **unions**, and **enums** should be **aligned**
  as much as possible (leave at least one tab between the type and the
  field name):

  .. code-block:: c

    struct             
    {                  
        DWORD   Field1;
        DWORD   Field2;
        char    Field3;
        int     Field4;
    } MY_STRUCTURE;    


- When defining **structure**, **union** or **enum types**, it is
  **recommended** to define the type with a preceding **underscore**
  and the pointer type as well:

  .. code-block:: c

    typedef struct _MY_STRUCT
    {                        
        DWORD   Field1;      
        DWORD   Field2;      
        char    Field3;      
        int     Field4;      
    } MY_STRUCT, *PMY_STRUCT;


- Do not abuse of **nameless structs/unions**; they should be used
  only when combining **structs** with **unions**, to provide **easy access** to the **inner members**:

  .. code-block:: c

    typedef union _MY_UNION    
    {                          
        DWORD       FullDword; 
        struct                 
        {                      
            BYTE    Byte0;     
            BYTE    Byte1;     
            BYTE    Byte2;     
            BYTE    Byte3;     
        };                     
    } MY_UNION;                

- **Bitfields** in types other than :code:`int` **are** accepted.
- It is strictly forbidden to use the suffix :code:`_t` in newly defined types.

Statements, code blocks, and curly braces
=========================================

- One line must contain **a single statement**.
- **Do not use the comma** to write multiple statements on a single
  line, **except** when declaring variables.
- The **semicolon** must be followed by a **newline**.
- The curly braces that **open** and **close** a code block must always
  be placed on **new lines**:

  .. code-block:: c

    if (c) 
    {      
        ...
    }      


- Each :code:`for`, :code:`while`, :code:`do`, :code:`if`, :code:`else`, or
  :code:`switch` must be followed by a new code block, even if they
  contain only one statement.
- Empty :code:`for`, :code:`while`, :code:`do` blocks must still contain an empty
  code block; do not place the semicolon immediately after the :code:`for`,
  :code:`while`, :code:`do` statements:

  .. code-block:: c

    for (i = 0; i < 100; j++, k++)
    {                             
        // void                   
    }                             

- The level of indentation for the curly braces is the same as the
  level used for the line before them; the code inside the new code
  block must be indented with one extra level:

  .. code-block:: c

    while (c)  
    {          
        c += 1;
        f(c);  
    }          

- :code:`switch` statements that do not cover all possible cases must
  contain a :code:`default` statement.
- :code:`if` statements that :code:`return` should not contain an :code:`else` statement. 
  Exceptions are allowed if a new scope needs to be opened, or for emulating a pattern matching style, 
  especially when using :code:`if else` constructs.

  .. code-block:: c

    if (c)                                   
    {                                        
        return 0;                            
    }                                        

    // Continue here, without writing an else


- :code:`while`, :code:`do`, :code:`for` statements with an always true/false condition are
  discouraged; if they are unavoidable, make sure the condition(s) for
  the :code:`break` statement is/are clear.
- Use of :code:`goto` is **forbidden**, **except** for a very special
  cleanup case: the destination label must be **at the end of the block** 
  and must do cleanup-specific operations; :code:`goto` to an inner
  block is **strictly forbidden** even for cleanup purposes:

  .. code-block:: c

        ...              

        if (error)       
        {                
            goto cleanup;
        }                

        ...              

    cleanup:             
        if (p)           
        {                
            free(p);     
        }                

        return 0;        
    }

- Labels must not be indented

  .. code-block:: c


        buf = HpAllocWithTag(Length, IC_TAG_ALLOC);
        if (NULL == buf)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto _clean_leave;
        }

        status = IntVirtMemRead(Gva, Length, cr3, buf, &retLen);
        if (!INT_SUCCESS(status))
        {
           ERROR("[ERROR] IntVirtMemRead failed for GVA 0x%016llx and length 0x%x: 0x%08x\n", Gva, Length, status);
           goto _clean_leave;
        }

        ...

    _clean_leave:
        if (buf != NULL)
        {
            HpFreeAndNullWithTag(&buf, IC_TAG_ALLOC);
        }
        return status;              

Conditions
==========

- Using assignments inside conditions **is forbidden** as it makes the
  code harder to read and reason about (of course, :code:`for` is an
  exception from this rule). For example, do not use any of the
  following:

  .. code-block:: c

    while ((i += 2) < 10)
    if ((a = f(x)) != c) 

- Simple pre/post increment/decrement within conditions **are allowed**:

  .. code-block:: c

    if (++i == 100)

- **Never** test against :code:`TRUE` or :code:`FALSE` using the equality operators

  .. code-block:: c

    if (foo) ...  // instead of "if (foo == TRUE)"                      
    if (!bar) ... // instead of "if (bar == FALSE)" or "if (bar != TRUE)"

- All loops must have a clear exit condition. For loops that are based
  on data obtained from the guest, an upper limit on the number of
  iterations must exist, or the range of the loop must be validated.
  For example, if iterating a memory range based on a length obtained
  from the guest, that length must be validated to not exceed an upper
  limit. If this is not possible, a limit on the number of iterations
  must be placed.
- Complex conditions will be placed on multiple lines, with the
  **operators placed at the end of the line**, and the conditions
  **aligned vertically** with the **condition block they belong to**:

  .. code-block:: c

    if ((Cache->Lines[line].Entries[i].Gva == Gva) && 
        Cache->Lines[line].Entries[i].Valid &&        
        ((Cache->Lines[line].Entries[i].Cr3 == Cr3) ||
         (IC_ANY_VAS == Cr3) ||                       
         (Cache->Lines[line].Entries[i].Global)))     


- Using parenthesis to surround **complex conditions** is **mandatory**. 
  **Using parenthesis for simple conditions is not mandatory and is discouraged**, 
  as it makes the code harder to read, longer, and it may create confusion, 
  hinting that another order of operations is imposed, not the implicit one

  .. code-block:: c

    if (a == b && (c == d || e == f))  

Lines length and spacing
========================

- Code and comment lines must **not be longer than 120 characters**. An
  exception is permitted for cases in which the limit is exceeded with
  only a few characters and does not hinder readability and does not
  hide information.
- Functions which are called with too many arguments will be split, in
  the most convenient way, to obey the 120 characters limit. Both of
  the following (splitting in the minimum number of lines
  **or** putting each argument on a different line) are accepted:

  .. code-block:: c

    status = IntLdrPreLoadImage(RawPe, RawPeSize, LoadedPe, VirtualPeSize, 
                                (DWORD)peInfo.NumberOfSections, pSections);

    memcpy(VirtualImage + Sections[i].VirtualAddress,            
           RawImage + Sections[i].PointerToRawData,              
           Sections[i].SizeOfRawData);                           


- The same rule applies to mathematical or logical operations that cross
  the 120 character limit, with the following lines aligned with the
  previous: 

  .. code-block:: c

    int foo = bar +
              baz; 


- Avoid writing multiple lines of code without blank lines in between.
- Functions should be separated by at least two blank lines.
- It is mandatory to leave at least one blank line before and after
  every :code:`if`, :code:`for`, :code:`while`, :code:`do`, :code:`switch` block.
- Comments right before such a statement, without a blank-line in between, are allowed.
- Try to insert blank lines in between unrelated sequences of operations:

  .. code-block:: c

    Flags &= HOOK_FLG_GLOBAL_MASK;                                   

    // This comment is allowed.                                      
    status = IntHookGpaDeleteHookInternal(*Hook, Flags);             
    if (!INT_SUCCESS(status))                                        
    {                                                                
        ERROR("[ERROR] IntHookGpaDeleteHookInternal failed: 0x%08x\n", status); 
    }                                                                

    *Hook = NULL;                                                    

    return INT_STATUS_SUCCESS;    

Documenting the code
====================

- All **functions**, **macros**, **structures**, **unions**, and
  **enums** must be documented using Doxygen_. Documentation must
  use 3 slashes (:code:`///`).
- Documentation for **macros**, **structure** and **union members**, or **enum values**
  can be placed on the same line as the documented field, using :code:`///<`. 
  Note that all these must be aligned. If such a comment needs to be split across multiple 
  lines it must be moved above the entity it documents.
- Each function documentation must contain **at least a brief description** 
  of the function. If more details are needed these can be added after the brief.
- Each parameter must be documented using :code:`@param` and specifying its type (input, output, or both).
- If the function returns a small set of known values, each value
  should be documented using :code:`@retval`; otherwise, :code:`@returns` can
  be used to describe the values that can be returned:

  .. code-block:: c
    
    INTSTATUS                      
    IntFoo(                        
        _In_ const char *Input,    
        _Out_ char* Output,        
        _Inout_opt_ char *Inout    
        )                          
    ///                            
    /// @brief Brief description.  
    ///                            
    /// More details, if needed.   
    ///                            
    /// @param[in]      Input   ...
    /// @param[out]     Output  ...
    /// @param[in, out] Inout   ...
    ///                            
    /// @retval INT_STATUS_...     
    /// @retval INT_STATUS_...     
    ///                            
    {                              
        ...                        
    }                              

- **Structures**, **unions**, and **enums** follow the same rules. Each field must
  be documented either on the same line as it is declared, using
  :code:`///<`, or on the line above the line it is declared on. If
  documentation needs to be split across multiple lines do not use
  :code:`///<`.
- Avoid writing comments for obvious pieces of code. Try to add more
  detailed comments before specific operations. This can be done using
  multi-line :code:`//` comments. 
  **Do not** use the multi-line :code:`/* */` to add comments inside functions. Example:

  .. code-block:: c

    // There can be only one pending #PF injection from swapmem at any given time, no matter how many CPUs we have.
    // However, make sure that the pending page is the same as the page for which an injection was requested, in order
    // to not cancel a valid transaction due to an injection error from an unrelated exception.
    if (NULL != gSwapState.PendingPage && (gSwapState.PendingPage->VirtualAddress & PAGE_MASK) == (VirtualAddress & PAGE_MASK))
    {
        TRACE("[SWAPMEM] Canceling pending #PF for 0x%016llx, CR3 0x%016llx, CPU %d...\n",
            gSwapState.PendingPage->VirtualAddress, gSwapState.PendingPage->Transaction->Cr3, gVcpu->Index);

        // All other faults need to wait.
        gSwapState.PendingPage->IsReady = TRUE;
        gSwapState.PendingPage->IsPending = FALSE;
        gSwapState.PendingPage->IsDone = FALSE;
        gSwapState.PendingPage->TimeStamp = 0;

        gSwapState.PendingPage = NULL;
    }

Defensive Coding
================

Error handling
--------------

- All functions that can fail must return an appropriate :code:`INTSTATUS`
  value that describes the failure reason (definitions are available in the `introstatus.h`_ header). 
  Exceptions can be made for simple functions that return a pointer (such as functions that search an
  object inside a list, or functions that allocate an object): these
  functions can return :code:`NULL` to signal an error.
- All the calls to functions that return :code:`INTSTATUS` values must be
  followed by a success check using the :code:`INT_SUCCESS` macro, or by
  explicit checking against expected status values.
- **Output arguments** passed to these functions are **invalid** if
  the function does not exit with success and should not be used.
- Calls to functions that **return pointers** must be followed by a :code:`NULL` pointer check.
- **Errors** must be **propagated** back to the caller if the error
  affects the current operation. Sometimes this implies translating an
  error status to another status. It is recommended to log errors when
  they appear as this can make debugging easier when reading Introcore
  logs:

  .. code-block:: c


    status = IntPeValidateHeader(Module->VirtualBase, pPage, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed for module at 0x%016llx: 0x%08x\n", Module->VirtualBase, status);
        return status;
    }

    proc = IntWinProcFindObjectByPid(pid);
    if (NULL == proc)
    {
        ERROR("[ERROR] IntWinProcFindObjectByPid failed for %d\n", pid);
        return INT_STATUS_NOT_FOUND;
    }

- The :code:`INTSTATUS` definition is annotated with :code:`_Return_type_success_`,
  functions that use other return types (or functions that return a specific status to signal success)
  may need to be manually annotated with :code:`_Success_`. While this
  is good practice, the current coding style does not enforce it. 
- Parameter checking is mandatory for functions that can be called from other modules:

  .. code-block:: c

    INTSTATUS
    IntHookGpaEnableHook(
        _In_ HOOK_GPA *Hook)
    {
        if (NULL == Hook)
        {
            return INT_STATUS_INVALID_PARAMETER_1;
        }

        ...
    }

- Internal, static function can skip the parameter checks.
- Handling cleanup in case of errors can be done by using :code:`goto`,
  simulating a poor version of :code:`__try/__leave`. Note that this is the 
  only scenario in which :code:`goto` is allowed. This offers a
  centralized way of exiting the function and makes the control flow
  easier to follow.
- Functions must be written in such a way that all success paths set
  all the output parameters, even if the value used for setting them is
  a default one. In other words, functions should not assume that an
  output parameter is pre-initialized in any way by the caller.
- Critical failures, which cannot be gracefully treated, and for which
  a dump file will help, can be treated by calling :code:`IntEnterDebugger()` or 
  :code:`IntBugCheck()`, but note that these functions will crash Introcore, 
  which will hang or crash the introspected VMs.

Variable initialization
-----------------------

- It may be tempting to pre-initialize a variable as soon as it is
  declared. Note that this can hide bugs, for example, the following
  code will hide a :code:`IntVirtMemMap` error:

  .. code-block:: c

    INTSTATUS status = INT_STATUS_SUCCESS;
    ...
    IntVirtMemMap(gva, length, 0, 0, &ptr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVIrtMemMap failed for [0x%016llx, 0x%016llx): 0x%08x\n", gva, gva + length, status);
        return status;
    }

- This guide does not explicitly forbid pre-initialization, as it is
  sometimes needed. Take for example the following code, where :code:`IntKernVirtMemRead` 
  will read from :code:`processFlinkGva` into :code:`nextFlink` :code:`gGuest.WordSize` bytes. 
  This works as intended for 64-bit guests. But for a 32-bit guest this will read 4 bytes into
  a :code:`QWORD`. Since :code:`**IntKernVirtMemRead` receives the output buffer as a :code:`BYTE` 
  pointer it can not properly zero the upper half of the :code:`nextFlink` variable. 
  This problem can be avoided by branching based on the type of the guest, and reading the value into
  a :code:`DWORD` for 32-bit guests, but that will needlessly duplicate the code. 
  In this situation the code is better and cleaner if the :code:`nextFlink` variable is pre-initialized to 0, 
  or if the upper 32-bits are cleared after the :code:`IntKernVirtMemRead` call:

  .. code-block:: c

    QWORD nextFlink;    
    status = IntKernVirtMemRead(processFlinkGva, gGuest.WordSize, &nextFlink, NULL);

- When initializing complex structures, unions, or even arrays, it is
  recommended to use designated initializers

  .. code-block:: c

    DEBUGGER_COMMAND help =
    {
        .Command = "!help",
        .Help = "show help",
        .FunctionNoArgs = _DbgShowHelp,
    };

- When initializing arrays, both of the following variants are
  accepted, although the first one is preferred for short initializers,
  and the second one for longer initializers

  .. code-block:: c

    DWORD shortArr[4] = { 1, 2, 3, 4 };

    DWORD longArr[16] = 
    {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16
    };

- It is recommended to **not** pre-initialize variables **blindly**,
  but to take into consideration the context in which a variable is used.

Using locks
-----------

- Introcore events and API calls must always be serialized. To allow
  this, all Introcore entry points must acquire the global
  :code:`gLock` lock and release it before returning control back to the
  integrator. Other locks are not needed.

Memory management
-----------------

- Memory must be allocated and freed using the :code:`HpAllocWithTag` and :code:`HpFreeAndNullWithTag` macros.
- Even if the allocation tag is not used by the default allocator, it must still be unique and defined in the 
  `memtags.h`_ header.
- Any :code:`HpAllocWithTag` call can fail so all the pointers returned by it must be checked against 
  :code:`NULL` before being used.
- When allocating memory for a structure or an array try to avoid using the type explicitly, and use the variable instead.

  .. code-block:: c

    INSTRUX *instruction = HpAllocWithTag(sizeof(*instruction), IC_TAG_FOO); // instead of "sizeof(INSTRUX)"

- When writing an Introcore module, try to follow the same convention as the other ones: use 
  **handles** to identify objects (hooks, events, etc.). Removing that object must be done via the handle. 
  For example, when placing a memory hook, a handle is returned. To remove that memory hook, the handle is 
  passed to the removal function; try to follow the same convention.

Variable length arrays
----------------------

- Declare variable length arrays using :code:`[]`, instead of :code:`[0]`.

- Always check that the array fits inside the buffer which is currently being parsed.

Using data obtained from the guest
----------------------------------

All data obtained from the guest is **untrusted**, especially when parsing complex structures:

- **Length fields must be capped** - the maximum value is
  context-dependent so this guide will not recommend one, but make sure
  the length is not negative, or too large (for example, 4 billion);
- **Relative offsets inside a buffer** - must be checked to avoid
  buffer overflows;
- **Strings must not be trusted to be NULL-terminated** - reading until
  a NULL-terminator is found is discouraged and, if not avoidable, must
  have an upper limit on the number of characters read; the
  NULL-terminator must be manually added to strings obtained from the
  guest;
- **Be careful with integer overflows** - when doing arithmetic on
  values read from the guest, pay attention to potential **integer overflow**; 
  for example, adding the section size to a section RVA may
  lead to an integer overflow, which may lead to an exploitable
  vulnerability;
- **Pay attention to the VA space** - when accessing guest data, make
  sure you use the correct CR3/VA space. Kernel data should always be
  accessed using the **SystemCr3**;
- **Pay attention to uninitialized variables** - when reading data
  smaller than the destination variable (for example, reading a DWORD
  into a QWORD variable), make sure you either pre-initialize the
  variable to 0, or mask it with the appropriate size after the read;
- Use :code:`IntVirtMemSafeWrite` when writing to unknown guest memory -
  when writing data inside the guest at an address that is unknown, or
  it is provided by an in-guest agent, use :code:`IntVirtMemSafeWrite`
  instead of :code:`IntKernVirtMemWrite`; the former validates both
  in-guest page-table and EPT accesses in order to make sure an
  in-guest attacker doesn't fool Introcore into writing otherwise
  read-only memory;
- **Watch out for TOCTOU (time of check vs. time of use)** - when
  operating on directly mapped guest pages, all checks should be done
  on internally cached values; otherwise, due to an attacker (or even
  during normal guest operation), previously checked & validated values
  may change, leading to potential issues.

Code review
===========

All code changes must be reviewed before being merged into the
development or master branch. We recommend using branches for this:
features should always be developed on dedicated feature branches. They
will be merged on develop only after code review and after sufficient
testing has been done from the feature branch. As a general
rule, `GitFlow <https://datasift.github.io/gitflow/IntroducingGitFlow.html>`__
should be used.

Static analysis
===============

Microsoft SAL
-------------

As mentioned earlier, Introcore functions are annotated using some basic
SAL annotations. Introcore doesn't use the entire range of annotations
available. At a minimum, these include:

- :code:`_In_` - input parameter, already initialized by the caller;
  pointers can not be :code:`NULL`.
- :code:`_Out_` - output parameter, the caller is not expected to
  initialize this in any way; set by the function on success; pointers
  can not be :code:`NULL`.
- :code:`_Inout_` - input and output parameter, already initialized by
  the caller; set by the function on success; pointers can not be :code:`NULL`.
- :code:`_In_opt_` - same as :code:`_In_`, but :code:`NULL` pointers are
  expected and are not considered invalid.
- :code:`_Out_opt_` - same as :code:`_Out_`, but :code:`NULL` pointers are
  expected and are not considered invalid.
- :code:`_Inout_Opt_` - same as :code:`_Inout_`, but :code:`NULL` pointers are
  expected and are not considered invalid.

The :code:`INTSTATUS` type is already annotated with :code:`_Return_type_success_(return >= 0)`. 
:code:`_Success_` can be used to describe the success return value for other functions.

Apart from the static analysis that can be run, this small subset
doubles as a quick way of documenting the parameters of a function.
Other constructs are encouraged, but people who are not used to SAL
might find it difficult to use, at first, so only the above sub-set is
mandatory. 

For more information see `Understanding SAL`_.

clang tidy
----------

Introcore also uses **clang-tidy**. It can be invoked from the command line:

.. code-block:: console

    cmake --build <build directory> --target tidy

For more information about clang tidy see `the official documentation <https://clang.llvm.org/extra/clang-tidy/>`__.

.. _Microsoft SAL: https://docs.microsoft.com/en-us/cpp/code-quality/using-sal-annotations-to-reduce-c-cpp-code-defects?view=vs-2019
.. _Doxygen: http://www.doxygen.nl/
.. _introstatus.h: ../_static/doxygen/html/introstatus_8h.html
.. _memtags.h: ../html/_static/doxygen/html/memtags_8h.html
.. _Understanding SAL: https://docs.microsoft.com/en-us/cpp/code-quality/understanding-sal?view=vs-2019
