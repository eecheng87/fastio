#ifndef INTERNAL_LIOO_H
#define INTERNAL_LIOO_H

/*
 * Header for kernel space
 */

/* Limit */
#define CPU_NUM_LIMIT 100
#define TABLE_LEN_LIMIT 10
#define TABLE_ENT_LIMIT 64
#define WORKQUEUE_DEFAULT_THREAD_NUMS 32
#define MAX_DEFERRED_NUM 256
#define MAX_OFFLOADED 2048

/* define flags */
#define ESCA_WORKER_NEED_WAKEUP (1U << 1)
#define ESCA_START_WAKEUP (1U << 2)

/* flags for context */
#define CTX_FLAGS_MAIN_DONE (1U << 1)
#define CTX_FLAGS_MAIN_WOULD_SLEEP (1U << 2)
#define CTX_FLAGS_WAKEUP_FROM_WQ (1U << 3)

#include "config.h"

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
    int ctx_id;
    int wq_wrk_id;
    struct list_head* self;
} esca_wkr_args_t;

/* store in first entry of each esca_table */

typedef struct esca_info {

} esca_info_t;

typedef struct esca_meta {
    esca_table_t table[TABLE_LEN_LIMIT];
    esca_info_t info[TABLE_LEN_LIMIT];
} esca_meta_t;

esca_config_t* config;

/* flags for workqueue */
#define WQ_FLAGS_IS_RUNNING (1U << 1)

struct fastio_work_node {
    int table;
    int cache_comp_num;
    int status;
    spinlock_t wrk_lock;
    struct task_struct* task;
    struct list_head list;
};
struct fastio_work_node* work_node_reg[WORKQUEUE_DEFAULT_THREAD_NUMS];

struct fastio_work_meta {
    int len;
    struct list_head list;
};

struct fastio_ctx {
    spinlock_t cq_lock;
    spinlock_t df_lock;
    spinlock_t comp_lock;
    int df_mask; /* MAX_DEFERRED_NUM - 1 */
    int df_head[WORKQUEUE_DEFAULT_THREAD_NUMS]; /* to be consumed */
    int df_tail[WORKQUEUE_DEFAULT_THREAD_NUMS]; /* to be post */
    int comp_num;
    unsigned idle_time; // FIXME: might be private to each wq-worker
    unsigned int wq_status; // set bit if worker isn't been blocked
    unsigned int wq_has_finished; // set bit if there is at least one task completed
    int status;
    esca_table_entry_t deferred_list[WORKQUEUE_DEFAULT_THREAD_NUMS][MAX_DEFERRED_NUM];
};
struct fastio_ctx* ctx[TABLE_LEN_LIMIT];

/* forward declaration */
static void create_worker_pool(int, int);
// static int main_worker(void*);
// static int wq_worker(void*);

#endif