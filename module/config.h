#ifndef _CONFIG_H
#define _CONFIG_H

/*
 * Header shared b/t user and kernel
 */

#define CONFIG_ARG_MAX_BYTES 128

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

#endif