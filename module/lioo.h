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
    int default_idle_time;
    int affinity_offset;
} esca_config_t;

static const esca_config_t default_config
    = {
          .esca_localize = 1,
          .max_table_entry = 64,
          .max_table_len = 1,
          .max_usr_worker = 1,
          .max_ker_worker = 1,
          .default_idle_time = 150,
          .affinity_offset = 0
      };

esca_config_t* config;

/* workqueue */
struct fastio_work_node {
	struct fastio_work_node *next;
};

struct io_wq_work_list {
	struct io_wq_work_node *first;
	struct io_wq_work_node *last;
};

#endif