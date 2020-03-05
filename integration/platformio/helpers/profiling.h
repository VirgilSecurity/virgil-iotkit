#ifndef VS_PROFILING_H
#define VS_PROFILING_H

#include <stdint.h>
#include <esp_timer.h>

static long long _processing_time_ms;
static long _calls_counter = 0;

static inline long long
current_timestamp() {
    return esp_timer_get_time();
}

#define VS_PROFILE_START                                                                                               \
    long long t;                                                                                                       \
    long long dt;                                                                                                      \
    do {                                                                                                               \
        _calls_counter++;                                                                                              \
        t = current_timestamp();                                                                                       \
    } while (0)

#define VS_PROFILE_END(DIV, DESC, UNIT)                                                                                \
    do {                                                                                                               \
        dt = current_timestamp() - t;                                                                                  \
        _processing_time_ms += (dt / 1000);                                                                            \
        VS_LOG_DEBUG("[" #DESC "]. Time op = %lld " #UNIT " Total time: %lld ms Calls: %ld",                           \
                     (dt / DIV),                                                                                       \
                     _processing_time_ms,                                                                              \
                     _calls_counter);                                                                                  \
    } while (0)

#define VS_PROFILE_END_IN_MS(DESC) VS_PROFILE_END(1000, DESC, ms)

#define VS_PROFILE_END_IN_MKS(DESC) VS_PROFILE_END(1, DESC, us)

#endif // VS_PROFILING_H
