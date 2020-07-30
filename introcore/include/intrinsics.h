/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTRINSICS_H_
#define _INTRINSICS_H_

#include <stddef.h>
#include <stdint.h>

#ifndef INT_COMPILER_MSVC

//
// Bit Twiddling
//
static inline uint8_t
_rotl8(uint8_t Value, uint8_t Shift)
{
    Shift &= 0x7;
    return Shift ? (Value << Shift) | (Value >> (8 - Shift)) : Value;
}

static inline uint8_t
_rotr8(uint8_t Value, uint8_t Shift)
{
    Shift &= 0x7;
    return Shift ? (Value >> Shift) | (Value << (8 - Shift)) : Value;
}

static inline uint16_t
_rtol16(uint16_t Value, uint8_t Shift)
{
    Shift &= 0xf;
    return Shift ? (Value << Shift) | (Value >> (16 - Shift)) : Value;
}

static inline uint16_t
_rotr16(uint16_t Value, uint8_t Shift)
{
    Shift &= 0xf;
    return Shift ? (Value >> Shift) | (Value << (16 - Shift)) : Value;
}


//
// Bit Counting and Testing
//
static inline uint8_t
_BitScanForward(uint32_t *Index, uint32_t Mask)
{
    if (!Mask)
        return 0;
    *Index = __builtin_ctzl(Mask);
    return 1;
}

static inline uint8_t
_BitScanReverse(uint32_t *Index, uint32_t Mask)
{
    if (!Mask)
        return 0;
    *Index = 31 - __builtin_clzl(Mask);
    return 1;
}

static inline uint32_t
_mm_popcnt_u32(uint32_t Value)
{
    return __builtin_popcount(Value);
}

static inline uint8_t
_bittest(int32_t const *BitBase, int32_t BitPos)
{
    return (*BitBase >> BitPos) & 1;
}

static inline uint8_t
_bittestandcomplement(int32_t *BitBase, int32_t BitPos)
{
    uint8_t _Res = (*BitBase >> BitPos) & 1;
    *BitBase = *BitBase ^ (1 << BitPos);
    return _Res;
}

static inline uint8_t
_bittestandreset(int32_t *BitBase, int32_t BitPos)
{
    uint8_t _Res = (*BitBase >> BitPos) & 1;
    *BitBase = *BitBase & ~(1 << BitPos);
    return _Res;
}

static inline uint8_t
_bittestandset(int32_t *BitBase, int32_t BitPos)
{
    uint8_t _Res = (*BitBase >> BitPos) & 1;
    *BitBase = *BitBase | (1 << BitPos);
    return _Res;
}


static inline uint8_t
_BitScanForward64(uint32_t *Index, uint64_t Mask)
{
    if (!Mask)
        return 0;
    *Index = __builtin_ctzll(Mask);
    return 1;
}

static inline uint8_t
_BitScanReverse64(uint32_t *Index, uint64_t Mask)
{
    if (!Mask)
        return 0;
    *Index = 63 - __builtin_clzll(Mask);
    return 1;
}

static inline uint64_t
_mm_popcnt_u64(uint64_t Value)
{
    return __builtin_popcountll(Value);
}

static inline uint8_t
_bittest64(int64_t const *BitBase, int64_t BitPos)
{
    return (*BitBase >> BitPos) & 1;
}

static inline uint8_t
_bittestandcomplement64(int64_t *BitBase, int64_t BitPos)
{
    uint8_t Res = (*BitBase >> BitPos) & 1;
    *BitBase = *BitBase ^ (1ll << BitPos);
    return Res;
}

static inline uint8_t
_bittestandreset64(int64_t *BitBase, int64_t BitPos)
{
    uint8_t Res = (*BitBase >> BitPos) & 1;
    *BitBase = *BitBase & ~(1ll << BitPos);
    return Res;
}

static inline uint8_t
_bittestandset64(int64_t *BitBase, int64_t BitPos)
{
    uint8_t Res = (*BitBase >> BitPos) & 1;
    *BitBase = *BitBase | (1ll << BitPos);
    return Res;
}


//
// readfs, readgs
// (Pointers in address space #256 and #257 are relative to the GS and FS
// segment registers, respectively.)
//
#ifdef INT_COMPILER_CLANG
#define __ptr_to_addr_space(__addr_space_nbr, __type, offset)              \
    ((volatile __type __attribute__((__address_space__(__addr_space_nbr)))*) \
    (offset))

static inline uint8_t
__readgsbyte(uint64_t offset)
{
    return *__ptr_to_addr_space(256, uint8_t, offset);
}

static inline uint16_t
__readgsword(uint64_t offset)
{
    return *__ptr_to_addr_space(256, uint16_t, offset);
}

static inline uint32_t
__readgsdword(uint64_t offset)
{
    return *__ptr_to_addr_space(256, uint32_t, offset);
}

static inline uint64_t
__readgsqword(uint64_t offset)
{
    return *__ptr_to_addr_space(256, uint64_t, offset);
}

#undef __ptr_to_addr_space

#endif

//
// movs, stos
//
static inline void
__movsb(uint8_t *dst, uint8_t const *src, size_t n)
{
    __asm__("rep movsb" : "+D"(dst), "+S"(src), "+c"(n));
}

static inline void
__movsd(uint32_t *dst, uint32_t const *src, size_t n)
{
    __asm__("rep movsl" : "+D"(dst), "+S"(src), "+c"(n));
}

static inline void
__movsw(uint16_t *dst, uint16_t const *src, size_t n)
{
    __asm__("rep movsh" : "+D"(dst), "+S"(src), "+c"(n));
}

static inline void
__stosb(uint8_t *dst, uint8_t x, size_t n)
{
    __asm__("rep stosb" : "+D"(dst), "+c"(n) : "a"(x));
}

static inline void
__stosd(uint32_t *dst, uint32_t x, size_t n)
{
    __asm__("rep stosl" : "+D"(dst), "+c"(n) : "a"(x));
}

static inline void
__stosw(uint16_t *dst, uint16_t x, size_t n)
{
    __asm__("rep stosh" : "+D"(dst), "+c"(n) : "a"(x));
}

static inline void
__movsq(uint64_t *dst, uint64_t const *src, size_t n)
{
    __asm__("rep movsq" : "+D"(dst), "+S"(src), "+c"(n));
}

static inline void
__stosq(uint64_t *dst, uint64_t x, size_t n)
{
    __asm__("rep stosq" : "+D"(dst), "+c"(n) : "a"(x));
}

//
// Misc
//
static inline void *
_AddressOfReturnAddress(void)
{
    return (void *)((int8_t *)__builtin_frame_address(0) + sizeof(void *));
}

static inline void *
_ReturnAddress(void)
{
    return __builtin_return_address(0);
}

static inline void
__cpuid(int32_t info[4], int32_t level)
{
    __asm__("cpuid" : "=a"(info[0]), "=b" (info[1]), "=c"(info[2]), "=d"(info[3])
            : "a"(level));
}

static inline void
__cpuidex(int32_t info[4], int32_t level, int32_t ecx)
{
    __asm__("cpuid" : "=a"(info[0]), "=b" (info[1]), "=c"(info[2]), "=d"(info[3])
            : "a"(level), "c"(ecx));
}

static inline uint64_t
_xgetbv(uint32_t xcr_no)
{
    uint32_t __eax, __edx;
    __asm__("xgetbv" : "=a" (__eax), "=d" (__edx) : "c" (xcr_no));
    return ((uint64_t)__edx << 32) | __eax;
}

static inline void
__halt(void)
{
    __asm__ volatile ("hlt");
}

// __builtin_prefetch expects a compile-time constant
// and sometimes it won't detect it with __forceinline
// The GCC's prefetch takes three arguments: address, readwrite and hint
// It will generate a PREFETCH or PREFETCHW depending on readwrite
// For now use only readwrite=0 (the default on MSVC)
#define _mm_prefetch(p, i) __builtin_prefetch(p, 0, i)

#ifndef INT_COMPILER_CLANG

static inline void
_mm_pause(void)
{
    __asm__ __volatile__("pause");
}

static inline uint64_t
__rdtsc(void)
{
    return __builtin_ia32_rdtsc();
}

#endif


//
// Privileged intrinsics
//
static inline uint64_t
__readmsr(uint32_t reg)
{
    // Loads the contents of a 64-bit model specific register (MSR) specified in
    // the ECX register into registers EDX:EAX. The EDX register is loaded with
    // the high-order 32 bits of the MSR and the EAX register is loaded with the
    // low-order 32 bits. If less than 64 bits are implemented in the MSR being
    // read, the values returned to EDX:EAX in unimplemented bit locations are
    // undefined.
    uint32_t edx;
    uint32_t eax;
    __asm__("rdmsr" : "=d"(edx), "=a"(eax) : "c"(reg));
    return (((uint64_t)edx) << 32) | (uint64_t)eax;
}

static inline uint64_t
__readcr0(void)
{
    uint64_t cr0_val;
    __asm__ __volatile__("mov %%cr0, %0" : "=q"(cr0_val) : : "memory");
    return cr0_val;
}

static inline uint64_t
__readcr3(void)
{
    uint64_t cr3_val;
    __asm__ __volatile__("mov %%cr3, %0" : "=q"(cr3_val) : : "memory");
    return cr3_val;
}

static inline uint64_t
__readcr4(void)
{
    uint64_t cr4_val;
    __asm__ __volatile__("mov %%cr4, %0" : "=q"(cr4_val) : : "memory");
    return cr4_val;
}

static inline uint64_t
__readcr8(void)
{
    uint64_t cr8_val;
    __asm__ __volatile__("mov %%cr8, %0" : "=q"(cr8_val) : : "memory");
    return cr8_val;
}

static inline void
__writecr0(uint64_t cr0_val)
{
    __asm__("mov %0, %%cr0" : : "q"(cr0_val) : "memory");
}

static inline void
__writecr3(uint64_t cr3_val)
{
    __asm__("mov %0, %%cr3" : : "q"(cr3_val) : "memory");
}

static inline void
__writecr4(uint64_t cr4_val)
{
    __asm__("mov %0, %%cr4" : : "q"(cr4_val) : "memory");
}

static inline void
__writecr8(uint64_t cr8_val)
{
    __asm__("mov %0, %%cr8" : : "q"(cr8_val) : "memory");
}

static inline void
__invlpg(void *Address)
{
    __asm__ __volatile__("invlpg (%0)" : : "b"(Address) : "memory");
}

static inline uint8_t
_interlockedbittestandset(int32_t volatile *BitBase, int32_t BitPos)
{
    int32_t _PrevVal = __atomic_fetch_or(BitBase, 1l << BitPos, __ATOMIC_SEQ_CST);
    return (_PrevVal >> BitPos) & 1;
}

static inline uint8_t
_interlockedbittestandreset(int32_t volatile *BitBase, int32_t BitPos)
{
    int32_t _PrevVal = __atomic_fetch_and(BitBase, ~(1l << BitPos), __ATOMIC_SEQ_CST);
    return (_PrevVal >> BitPos) & 1;
}

static inline uint8_t
_interlockedbittestandset64(int64_t volatile *BitBase, int64_t BitPos)
{
    int64_t _PrevVal = __atomic_fetch_or(BitBase, 1ll << BitPos, __ATOMIC_SEQ_CST);
    return (_PrevVal >> BitPos) & 1;
}


//
// Interlocked Exchange Add
//
static inline int8_t
_InterlockedExchangeAdd8(int8_t volatile *Addend, int8_t Value)
{
    return __atomic_fetch_add(Addend, Value, __ATOMIC_SEQ_CST);
}

static inline int16_t
_InterlockedExchangeAdd16(int16_t volatile *Addend, int16_t Value)
{
    return __atomic_fetch_add(Addend, Value, __ATOMIC_SEQ_CST);
}


static inline int64_t
_InterlockedExchangeAdd64(int64_t volatile *Addend, int64_t Value)
{
    return __atomic_fetch_add(Addend, Value, __ATOMIC_SEQ_CST);
}


//
// Interlocked Increment
//
static inline int32_t
_InterlockedIncrement(int32_t volatile *Value)
{
    return __atomic_add_fetch(Value, 1, __ATOMIC_SEQ_CST);
}

static inline int16_t
_InterlockedIncrement16(int16_t volatile *Value)
{
    return __atomic_add_fetch(Value, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t
_InterlockedIncrement64(int64_t volatile *Value)
{
    return __atomic_add_fetch(Value, 1, __ATOMIC_SEQ_CST);
}


//
// Interlocked Decrement
//
static inline int32_t
_InterlockedDecrement(int32_t volatile *Value)
{
    return __atomic_sub_fetch(Value, 1, __ATOMIC_SEQ_CST);
}

static inline int16_t
_InterlockedDecrement16(int16_t volatile *Value)
{
    return __atomic_sub_fetch(Value, 1, __ATOMIC_SEQ_CST);
}

static inline int64_t
_InterlockedDecrement64(int64_t volatile *Value)
{
    return __atomic_sub_fetch(Value, 1, __ATOMIC_SEQ_CST);
}


//
// Interlocked And
//
static inline int8_t
_InterlockedAnd8(int8_t volatile *Value, int8_t Mask)
{
    return __atomic_and_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int16_t
_InterlockedAnd16(int16_t volatile *Value, int16_t Mask)
{
    return __atomic_and_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int32_t
_InterlockedAnd(int32_t volatile *Value, int32_t Mask)
{
    return __atomic_and_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int64_t
_InterlockedAnd64(int64_t volatile *Value, int64_t Mask)
{
    return __atomic_and_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}


//
// Interlocked Or
//
static inline int8_t
_InterlockedOr8(int8_t volatile *Value, int8_t Mask)
{
    return __atomic_or_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int16_t
_InterlockedOr16(int16_t volatile *Value, int16_t Mask)
{
    return __atomic_or_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int32_t
_InterlockedOr(int32_t volatile *Value, int32_t Mask)
{
    return __atomic_or_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int64_t
_InterlockedOr64(int64_t volatile *Value, int64_t Mask)
{
    return __atomic_or_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}


//
// Interlocked Xor
//
static inline int8_t
_InterlockedXor8(int8_t volatile *Value, int8_t Mask)
{
    return __atomic_xor_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int16_t
_InterlockedXor16(int16_t volatile *Value, int16_t Mask)
{
    return __atomic_xor_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int32_t
_InterlockedXor(int32_t volatile *Value, int32_t Mask)
{
    return __atomic_xor_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}

static inline int64_t
_InterlockedXor64(int64_t volatile *Value, int64_t Mask)
{
    return __atomic_xor_fetch(Value, Mask, __ATOMIC_SEQ_CST);
}


//
// Interlocked Exchange
//
static inline int32_t
_InterlockedExchange(int32_t volatile *Target, int32_t Value)
{
    __atomic_exchange(Target, &Value, &Value, __ATOMIC_SEQ_CST);
    return Value;
}

static inline int8_t
_InterlockedExchange8(int8_t volatile *Target, int8_t Value)
{
    __atomic_exchange(Target, &Value, &Value, __ATOMIC_SEQ_CST);
    return Value;
}

static inline int16_t
_InterlockedExchange16(int16_t volatile *Target, int16_t Value)
{
    __atomic_exchange(Target, &Value, &Value, __ATOMIC_SEQ_CST);
    return Value;
}

static inline int64_t
_InterlockedExchange64(int64_t volatile *Target, int64_t Value)
{
    __atomic_exchange(Target, &Value, &Value, __ATOMIC_SEQ_CST);
    return Value;
}


//
// Interlocked Compare Exchange
//
static inline int8_t
_InterlockedCompareExchange8(int8_t volatile *Destination, int8_t Exchange, int8_t Comparand)
{
    __atomic_compare_exchange(Destination, &Comparand, &Exchange, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return Comparand;
}

static inline int16_t
_InterlockedCompareExchange16(int16_t volatile *Destination, int16_t Exchange, int16_t Comparand)
{
    __atomic_compare_exchange(Destination, &Comparand, &Exchange, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return Comparand;
}

static inline int32_t
_InterlockedCompareExchange(int32_t volatile *Destination, int32_t Exchange, int32_t Comparand)
{
    __atomic_compare_exchange(Destination, &Comparand, &Exchange, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return Comparand;
}

static inline int64_t
_InterlockedCompareExchange64(int64_t volatile *Destination, int64_t Exchange, int64_t Comparand)
{
    __atomic_compare_exchange(Destination, &Comparand, &Exchange, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return Comparand;
}

static inline void *
_InterlockedCompareExchangePointer(void volatile **Destination, void *Exchange, void *Comparand)
{
    return (void *)_InterlockedCompareExchange64((int64_t volatile *)Destination, (int64_t)Exchange, (int64_t)Comparand);
}


//
// Barriers
//
static inline void
__attribute__((__deprecated__("use other intrinsics or C++11 atomics instead")))
_ReadWriteBarrier(void)
{
    __asm__ volatile ("" : : : "memory");
}

static inline void
__attribute__((__deprecated__("use other intrinsics or C++11 atomics instead")))
_ReadBarrier(void)
{
    __asm__ volatile ("" : : : "memory");
}

static inline void
__attribute__((__deprecated__("use other intrinsics or C++11 atomics instead")))
_WriteBarrier(void)
{
    __asm__ volatile ("" : : : "memory");
}

static inline void
__faststorefence(void)
{
    __asm__ volatile("lock orq $0, (%%rsp)" : : : "memory");
}

#endif // INT_COMPILER_MSVC

#endif // _INTRINSICS_H_
