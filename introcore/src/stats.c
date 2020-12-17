/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   stats.c
/// @brief  Event measurement.
///
/// Offers a way to measure how many events of some kind were triggered and how much time it takes for introcore
/// to handle it. Event, in this case, can mean anything, from an entire VMEXIT event, to a smaller, more focused,
/// part of an algorithm. Each event is defined by a #STAT_ID. Stats can be nested. Normally, only the time an
/// event was triggered is measured (and this is usually enough to pin point performance problems). If
/// STATS_HAS_HIGHRES_TIMER is defined we will also measure the time needed for Introcore to handle that event. This
/// is usually not defined because it can leas to hypercalls to the hypervisor and the simple act of gathering this
/// information may create performance problems.
///

#include "guests.h"

/// @brief  The list of counters.
STAT_COUNTER gCounters[statsMaxCounter] = {0};

#ifdef STATS_HAS_HIGHRES_TIMER
/// @brief  The overhead of a time measurement.
static INT64 gStatCallTimeNs;
#endif

__pure
static const char *
IntStatGetName(
    _In_ STAT_ID StatId
    )
///
/// @brief  Returns the name of a #STAT_ID.
///
/// @param[in]  StatId  The ID of the stat.
///
/// @returns    The name of the ID or "<err_counter>" if the ID is not known.
///
{
#define __stats_case(x) case x: return &(#x[5])

    switch (StatId)
    {
        __stats_case(statsEptViolation);
        __stats_case(statsEptRead);
        __stats_case(statsEptWrite);
        __stats_case(statsEptExecute);
        __stats_case(statsEptKernel);
        __stats_case(statsEptUser);
        __stats_case(statsEptDecode);
        __stats_case(statsEptLookup);
        __stats_case(statsEptHandle);
        __stats_case(statsEptRMW);
        __stats_case(statsVmcall);
        __stats_case(statsCrViolation);
        __stats_case(statsMsrViolation);
        __stats_case(statsXcrViolation);
        __stats_case(statsTimer);
        __stats_case(statsInt3);
        __stats_case(statsDtrViolation);
        __stats_case(statsEventInjection);
        __stats_case(statsModuleLoadViolation);
        __stats_case(statsDeleteRegion);
        __stats_case(statsDeleteGva);
        __stats_case(statsHookCommit);
        __stats_case(statsPtWriteProc);
        __stats_case(statsPtWriteEmu);
        __stats_case(statsPtWriteTotal);
        __stats_case(statsPtWriteHits);
        __stats_case(statsPtWriteRelevant);
        __stats_case(statsExceptionsUser);
        __stats_case(statsExceptionsKern);
        __stats_case(statsExceptionsGlobMatch);
        __stats_case(statsUmCrash);
        __stats_case(statsVasmon);
        __stats_case(statsVadCommitExisting);
        __stats_case(statsPtsIntegrity);
        __stats_case(statsPtsFilterInt3);
        __stats_case(statsPtsFilterVmcall);
        __stats_case(statsPtsFilterInsSearch);
        __stats_case(statsSwapgsInsSearch);
        __stats_case(statsSelfMapEntryProtection);
        __stats_case(statsCopyMemoryTotal);
        __stats_case(statsCopyMemoryRead);
        __stats_case(statsCopyMemoryWrite);
        __stats_case(statsCopyMemoryProtectedRead);
        __stats_case(statsCopyMemoryProtectedWrite);
        __stats_case(statsDepViolation);
        __stats_case(statsStackTrace32);
        __stats_case(statsStackTrace64);
        __stats_case(statsStackTraceSpecialCase);
        __stats_case(statsDpiGatherInfo);
        __stats_case(statsDpiDebugFlag);
        __stats_case(statsDpiStackPivot);
        __stats_case(statsDpiStealToken);
        __stats_case(statsDpiHeapSpray);
        __stats_case(statsDpiTokenPrivs);
        __stats_case(statsDpiThreadStart);
        __stats_case(statsProcessCreationCheck);
        __stats_case(statsNtEatRead);
        __stats_case(statsTokenWrites);
        __stats_case(statsTokenChangeCheck);
        __stats_case(statsTokenSwapCheck);
        __stats_case(statsKmUmWrites);
        __stats_case(statsDpiSdAcl);
        __stats_case(statsSudIntegrity);
        __stats_case(statsSudExec);
        __stats_case(statsSecDesc);
        __stats_case(statsSetProcInfo);
        __stats_case(statsMaxCounter);
    }

    return "<err_counter>";

#undef __stats_case
}

static __forceinline void
GetTime(
    _Out_ TIMESPEC *Time
    )
///
/// @brief  Returns the current time.
///
/// If STATS_HAS_HIGHRES_TIMER is defined, this will use clock_gettime; if not, rdtsc Will be used.
///
/// @param[out] Time    The time.
///
{
#ifndef STATS_HAS_HIGHRES_TIMER
    *Time = __rdtsc();
#else
    clock_gettime(CLOCK_MONOTONIC, Time);
#endif
}


static __forceinline void
DiffTime(
    _In_ TIMESPEC const *End,
    _In_ TIMESPEC const *Start,
    _Out_ TIMESPEC *Result
    )
///
/// @brief  Computes the delta between two time values.
///
/// @param[in]  End     The end of the time interval.
/// @param[in]  Start   The start of the time interval.
/// @param[out] Result  The delta.
///
{
#ifdef STATS_HAS_HIGHRES_TIMER
    if (__likely(End->tv_nsec > Start->tv_nsec))
    {
        Result->tv_sec = End->tv_sec - Start->tv_sec;
        Result->tv_nsec = End->tv_nsec - Start->tv_nsec;
    }
    else
    {
        Result->tv_sec = End->tv_sec - Start->tv_sec - 1;
        Result->tv_nsec = NSEC_PER_SEC + End->tv_nsec - Start->tv_nsec;
    }
#else
    *Result = *End - *Start;
#endif
}


static __forceinline void
IncStatsCallsCount(
    void
    )
///
/// @brief  Computes the time #GetTime was called for each counter that was started before this one and on this event.
///
/// Does nothing if STATS_HAS_HIGHRES_TIMER is not defined.
///
{
#ifdef STATS_HAS_HIGHRES_TIMER
    for (DWORD i = 0; i < ARRAYSIZE(gCounters); i++)
    {
        if (gCounters[i].StartEventId == gEventId)
        {
            gCounters[i].StatCalls++;
        }
    }
#endif
}


static __forceinline void
AddToTime(
    _Inout_ TIMESPEC *Time,
    _In_ TIMESPEC const *Adder
    )
///
/// @brief  Adds two time values.
///
/// @param[in, out] Time    Value to which to add.
/// @param[in]      Adder   Value to add.
///
{
#ifdef STATS_HAS_HIGHRES_TIMER
    Time->tv_sec += Adder->tv_sec;
    Time->tv_nsec += Adder->tv_nsec;

    if (Time->tv_nsec >= (INT64)NSEC_PER_SEC)
    {
        ++Time->tv_sec;
        Time->tv_nsec -= NSEC_PER_SEC;
    }
#else
    *Time += *Adder;
#endif
}


void
IntStatsDumpAll(
    void
    )
///
/// @brief  Prints all the non-zero stats.
///
{
    LOG("[STATS] Introspection stats (totaling %lld events):\n", gEventId);

    for (DWORD i = 0; i < statsMaxCounter; i++)
    {
        // This is double the size of what we really need
        char line[255];
        STAT_COUNTER const *pCounter = &gCounters[i];

        if (0 == pCounter->TotalCount)
        {
            continue;
        }

#if defined(STATS_DISABLE_TIMER)
        snprintf(line, sizeof(line), "%20s: %12llu times\n", IntStatGetName(i), pCounter->TotalCount);

#elif defined(STATS_HAS_HIGHRES_TIMER)
        double t = (double)(pCounter->Total.tv_sec * NSEC_PER_SEC +
                            pCounter->Total.tv_nsec) / (double)pCounter->TotalCount;
        INT64 spe = 0;
        INT64 nspe = (INT64)t % NSEC_PER_SEC;

        for (INT64 j = (INT64)t; j >= (INT64)NSEC_PER_SEC; j -= NSEC_PER_SEC)
        {
            ++spe;
        }

        snprintf(line, sizeof(line),
                 "%25s: %8lld times - %4lu.%09lu (total) %4lld.%09lld (per exit) %4lld.%09lld (max)\n",
                 IntStatGetName(i), pCounter->TotalCount,
                 pCounter->Total.tv_sec, pCounter->Total.tv_nsec,
                 spe, nspe,
                 NSEC_TO_SEC(pCounter->Max), pCounter->Max % NSEC_PER_SEC);
#else
        snprintf(line, sizeof(line),
                 "%25s: %20llu CPU ticks %12llu times - %4.6f (total) %4.12f (per exit) %4.12f (max)\n",
                 IntStatGetName(i),
                 pCounter->Total, pCounter->TotalCount,
                 pCounter->Total / (double)gGuest.TscSpeed,
                 pCounter->Total / (double)gGuest.TscSpeed / (double)pCounter->TotalCount,
                 pCounter->Max / (double)gGuest.TscSpeed);
#endif

        LOG("%s\n", line);
    }
}


void
IntStatsReset(
    _In_ STAT_ID StatId
    )
///
/// @brief  Resets a stat.
///
/// @param[in]  StatId  Stat to reset.
///
{
    STAT_COUNTER *pCounter = &gCounters[StatId];

    pCounter->TotalCount = 0;

#ifndef STATS_DISABLE_TIMER
    pCounter->Max = 0;
    pCounter->StartEventId = 0;

    memset(&pCounter->Start, 0, sizeof(pCounter->Start));
#endif
}


void
IntStatsResetAll(
    void
    )
///
/// @brief  Resets all the stats.
///
{
    for (STAT_ID i = 0; i < statsMaxCounter; i++)
    {
        IntStatsReset(i);
    }
}


#ifndef STATS_DISABLE_TIMER

void
IntStatStart(
    _In_ STAT_ID StatId
    )
///
/// @brief  Starts a stat measurement.
///
/// Does nothing before the OS-specific parts of Introcore are initialized  (#IntWinGuestFinishInit for Windows
/// guests; #IntLixGuestNew for Linux guests) or if Introcore is preparing to unload.
///
/// Each call must be matched by a #IntStatStop call. Calling this function twice for the same #gEventId will
/// over-write the old measurement for this stat.
///
/// @param[in]  StatId  Stat for which to start the measurement.
///
{
    STAT_COUNTER *pCounter;

    if (__unlikely(gGuest.UninitPrepared || gEventId <= gGuest.IntroActiveEventId))
    {
        return;
    }

    pCounter = &gCounters[StatId];

    pCounter->StartEventId = gEventId;

    GetTime(&pCounter->Start);

    IncStatsCallsCount();

    pCounter->StatCalls = 0;
}


void
IntStatStop(
    _In_ STAT_ID StatId
    )
///
/// @brief  Stops a stat measurement.
///
/// Does nothing before the OS-specific parts of Introcore are initialized  (#IntWinGuestFinishInit for Windows
/// guests; #IntLixGuestNew for Linux guests) or if Introcore is preparing to unload.
///
/// Must be called after a #IntStatStart call.
///
/// @param[in]  StatId  Stat for which to stop the measurement.
///
{
    if (__unlikely(gGuest.UninitPrepared || gEventId <= gGuest.IntroActiveEventId))
    {
        return;
    }

    TIMESPEC total, end;
    STAT_COUNTER *pCounter = &gCounters[StatId];

    pCounter->TotalCount++;

    if (pCounter->StartEventId != gEventId)
    {
        if (pCounter->StartEventId != 0)
        {
            ERROR("[ERROR] StartCount on event id %lld and stop on %lld for counter %d\n",
                  pCounter->StartEventId, gEventId, StatId);
        }

        return;
    }

    GetTime(&end);

    IncStatsCallsCount();

    DiffTime(&end, &pCounter->Start, &total);

#ifndef STATS_HAS_HIGHRES_TIMER

    if (total > pCounter->Max)
    {
        pCounter->Max = total;
    }

#else

    QWORD totalNs = total.tv_sec * NSEC_PER_SEC + total.tv_nsec;
    QWORD statCallNs = pCounter->StatCalls * gStatCallTimeNs;

    // Subtract the time spent in clock_gettime (by how many times it was called)
    if (totalNs > statCallNs)
    {
        TIMESPEC t1;
        TIMESPEC oldTotal = total;

        t1.tv_sec = statCallNs / NSEC_PER_SEC;
        t1.tv_nsec = statCallNs - (t1.tv_sec * NSEC_PER_SEC);

        total.tv_nsec -= pCounter->StatCalls * gStatCallTimeNs;

        DiffTime(&oldTotal, &t1, &total);
    }

    if (totalNs > pCounter->Max)
    {
        pCounter->Max = totalNs;
    }

#endif // STATS_HAS_HIGHRES_TIMER

    AddToTime(&pCounter->Total, &total);

    pCounter->StartEventId = 0;
}

void
IntStatDiscard(
    _In_ STAT_ID StatId
    )
///
/// @brief  Discards the current measurement for a stat counter.
///
/// @param[in]  StatId  Counter to discard.
///
{
    gCounters[StatId].StartEventId = 0;
    gCounters[StatId].StatCalls = 0;
}

#endif // STATS_DISABLE_TIMER


void
IntStatsInit(
    void
    )
///
/// @brief  Initialization routine.
///
/// If STATS_HAS_HIGHRES_TIMER is defined will determine how much a #GetTime takes so we know how much to subtract when
/// a counter includes another counter.
{
#ifdef STATS_HAS_HIGHRES_TIMER
    const DWORD calibrationCalls = 10000;
    TIMESPEC start, end, total;

    GetTime(&start);

    for (DWORD i = 0; i < calibrationCalls; i++)
    {
        GetTime(&total);
    }

    GetTime(&end);

    DiffTime(&end, &start, &total);

    gStatCallTimeNs = (end.tv_nsec - start.tv_nsec) / calibrationCalls;

    // Allow a 10% error margin
    gStatCallTimeNs -= (gStatCallTimeNs / 10);

    LOG("[DEBUG] Calibrated clock_gettime timer to %lld nanoseconds\n", gStatCallTimeNs);
#endif
}
