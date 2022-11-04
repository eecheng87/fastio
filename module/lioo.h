#ifndef INTERNAL_LIOO_H
#define INTERNAL_LIOO_H

/*
 * Header for kernel space
 */

/* Limit */
#define CPU_NUM_LIMIT 100
#define TABLE_LEN_LIMIT 10
#define TABLE_ENT_LIMIT 64
#define CONFIG_ARG_MAX_BYTES 128
#define WORKQUEUE_DEFAULT_THREAD_NUMS 4
#define MAX_DEFERRED_NUM 64

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

/* Configuration */
typedef struct config_option {
    char key[CONFIG_ARG_MAX_BYTES];
    int val;
} config_option_t;

typedef struct esca_config {
    int esca_localize;
    int max_table_entry;
    int max_table_len;
    int max_usr_worker;
    int max_ker_worker;
    int default_main_worker_idle_time;
    int default_wq_worker_idle_time;
    int affinity_offset;
} esca_config_t;

static const esca_config_t default_config
    = {
          .esca_localize = 1,
          .max_table_entry = 64,
          .max_table_len = 1,
          .max_usr_worker = 1,
          .max_ker_worker = 1,
          .default_main_worker_idle_time = 150,
          .default_wq_worker_idle_time = 150,
          .affinity_offset = 0
      };

esca_config_t* config;

/* workqueue */
typedef enum work_status wrk_status;

enum work_status {
    RUNNING,
    IDLE
};

struct fastio_work_node {
    int table;
    int cache_comp_num;
    wrk_status status;
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
    spinlock_t l_lock;
    spinlock_t df_lock;
    spinlock_t comp_lock;
    int df_mask; /* MAX_DEFERRED_NUM - 1 */
    int df_head[WORKQUEUE_DEFAULT_THREAD_NUMS]; /* to be consumed */
    int df_tail[WORKQUEUE_DEFAULT_THREAD_NUMS]; /* to be post */
    int comp_num;
    unsigned idle_time; // in jiffies
    struct fastio_work_meta* running_list;
    struct fastio_work_meta* free_list;
    esca_table_entry_t deferred_list[WORKQUEUE_DEFAULT_THREAD_NUMS][MAX_DEFERRED_NUM];
};
struct fastio_ctx* ctx[TABLE_LEN_LIMIT];

/* forward declaration */
static void create_worker_pool(int, int);
// static int main_worker(void*);
// static int wq_worker(void*);

#endif