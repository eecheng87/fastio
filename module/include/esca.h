#ifndef _ESCA_H
#define _ESCA_H

/*
 * Header for userland
 */

#include "../config.h"
#include <stdatomic.h>

#define DEFAULT_CONFIG_PATH "/home/eecheng/fastio/esca.conf"
#define CONFIG_ARG_MAX_BYTES 128

/* Limit */
#define CPU_NUM_LIMIT 100
#define TABLE_LEN_LIMIT 10
#define TABLE_ENT_LIMIT 64

#define ESCA_WRITE_ONCE(var, val)                           \
    atomic_store_explicit((_Atomic __typeof__(var)*)&(var), \
        (val), memory_order_relaxed)
#define ESCA_READ_ONCE(var)                                \
    atomic_load_explicit((_Atomic __typeof__(var)*)&(var), \
        memory_order_relaxed)

#define esca_smp_store_release(p, v)                           \
    atomic_store_explicit((_Atomic __typeof__(*(p))*)(p), (v), \
        memory_order_release)

#define esca_smp_load_acquire(p)                         \
    atomic_load_explicit((_Atomic __typeof__(*(p))*)(p), \
        memory_order_acquire)

#ifndef esca_unlikely
#define esca_unlikely(cond) __builtin_expect(!!(cond), 0)
#endif

#ifndef esca_likely
#define esca_likely(cond) __builtin_expect(!!(cond), 1)
#endif

extern esca_config_t* config;

/* define flags */
#define ESCA_WORKER_NEED_WAKEUP (1U << 1)
#define ESCA_START_WAKEUP (1U << 2)

typedef struct esca_table_entry {
    unsigned pid;
    short nargs;
    short rstatus;
    unsigned sysnum;
    unsigned sysret;
    long args[6];
} esca_table_entry_t;

typedef struct esca_table {
    esca_table_entry_t* tables[TABLE_LEN_LIMIT]; // shared b/t kernel and user (in kernel address space)
    esca_table_entry_t* user_tables[TABLE_LEN_LIMIT]; // shared b/t kernel and user (in usr address space)
    short head_table; // entry for consumer
    short tail_table; // entry for producer
    short head_entry;
    short tail_entry;
    unsigned idle_time; // in jiffies
    unsigned int flags;
} esca_table_t;

typedef struct esca_wkr_args {
    int id;
} esca_wkr_args_t;

#endif
