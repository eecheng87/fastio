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
#define MAIN_WORKER_NEED_WAKEUP (1U << 1)
#define START_WAKEUP_MAIN_WORKER (1U << 2)
#define CTX_FLAGS_MAIN_WOULD_SLEEP (1U << 3)

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
    unsigned int wq_has_finished; // for SQ only; set bit if there is at least one task completed
    unsigned int main_has_finished;
} esca_table_t;

/* argument passed into new io-worker; used by main- and wq- worker */
typedef struct esca_wkr_args {
    int ctx_id;
    int wrk_id; // the index of the current worker in the context
    struct list_head* self;
} esca_wkr_args_t;

#endif
