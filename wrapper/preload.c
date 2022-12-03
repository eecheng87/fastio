#include "preload.h"
#include <sys/mman.h>

#if defined(__aarch64__)
#include "../module/include/aarch64_syscall.h"
#elif defined(__x86_64__)
#include "../module/include/x86_syscall.h"
#endif

int in_segment;
int main_pid;
int batch_num; /* number of busy entry */
int syscall_num; /* number of syscall triggered currently */
size_t pgsize;

void* mpool; /* memory pool */
struct iovec* iovpool; /* pool for iovector */
struct msghdr* msgpool; /* pool for msgpool */
ull pool_offset;
ull iov_offset;
ull msg_offset;

/* Global configurable variable */
int ESCA_LOCALIZE;
int MAX_TABLE_ENTRY;
int MAX_TABLE_LEN;
int MAX_USR_WORKER;
int MAX_CPU_NUM;
int RATIO;
int DEFAULT_MAIN_IDLE_TIME;
int DEFAULT_WQ_IDLE_TIME;
int AFF_OFF;

esca_config_t* config;

/* declare shared table, pin user space addr. to kernel phy. addr by kmap */
int this_worker_id;

// FIXME: encapsulate
/* user worker can't touch worker's table in diff. set */
esca_table_t* sq[CPU_NUM_LIMIT];
esca_table_t* cq[CPU_NUM_LIMIT];

void init_worker(int idx)
{
    esca_table_entry_t* alloc_cq = NULL;
    esca_table_t* cq_header = NULL;

    in_segment = 0;
    batch_num = 0;
    syscall_num = 0;

    /* expect idx = 0 ~ MAX_USR_WORKER - 1 */
    this_worker_id = idx;

    printf("Create worker ID = %d, pid = %d\n", this_worker_id, getpid());

    if (idx >= MAX_USR_WORKER) {
        printf("[ERROR] Process exceed limit\n");
        goto init_worker_exit;
    }

    for (int i = idx * RATIO; i < idx * RATIO + RATIO; i++) {
        /* headers in same set using a same page */
        esca_table_t* sq_header = NULL;
        esca_table_entry_t* alloc_sq = NULL;

        if (i == idx * RATIO) {
            sq_header = sq[i] = (esca_table_t*)aligned_alloc(pgsize, pgsize);
        }
        sq[i] = sq[idx * RATIO] + (i - idx * RATIO);

        /* allocate tables */
        alloc_sq = (esca_table_entry_t*)aligned_alloc(pgsize, pgsize * MAX_TABLE_LEN);

        if (!alloc_sq) {
            printf("[ERROR] alloc SQ failed\n");
            goto init_worker_exit;
        }

        /* pin tables to kernel */
        syscall(__NR_esca_register, sq_header, alloc_sq, i, REG_SQ);

        /* pin table from kernel to user */
        for (int j = 0; j < MAX_TABLE_LEN; j++) {
            sq[i]->user_tables[j] = alloc_sq + j * MAX_TABLE_ENTRY;
        }
    }

    /* each context has only one CQ */
    cq_header = cq[idx] = (esca_table_t*)aligned_alloc(pgsize, pgsize);
    alloc_cq = (esca_table_entry_t*)aligned_alloc(pgsize, pgsize * MAX_TABLE_LEN);

    if (!alloc_cq) {
        printf("[ERROR] alloc CQ failed\n");
        goto init_worker_exit;
    }

    /* The index of CQ is as same as context's */
    syscall(__NR_esca_register, cq_header, alloc_cq, idx * RATIO, REG_CQ);

    for (int j = 0; j < MAX_TABLE_LEN; j++) {
        cq[idx]->user_tables[j] = alloc_cq + j * MAX_TABLE_ENTRY;
    }

    mpool = (void*)malloc(sizeof(unsigned char) * MAX_POOL_SIZE);
    pool_offset = 0;
    iovpool = (struct iovec*)malloc(sizeof(struct iovec) * MAX_POOL_IOV_SIZE);
    iov_offset = 0;
    msgpool = (struct msghdr*)malloc(sizeof(struct msghdr) * MAX_POOL_MSG_SIZE);
    msg_offset = 0;

    asm volatile("" ::: "memory");

    /* launch workers */
    syscall(__NR_esca_register, NULL, NULL, idx, REG_LAUNCH);

init_worker_exit:
    return;
}

long batch_start()
{
    int i = this_worker_id;
    in_segment = 1;

    for (int j = i * RATIO; j < i * RATIO + RATIO; j++) {
        if (esca_unlikely(ESCA_READ_ONCE(sq[j]->flags) & MAIN_WORKER_NEED_WAKEUP)) {
            sq[j]->flags |= START_WAKEUP_MAIN_WORKER;
            syscall(__NR_esca_wakeup, j);
            sq[j]->flags &= ~START_WAKEUP_MAIN_WORKER;
        }
    }

    return 0;
}

void peek_main_worker()
{
    int i = this_worker_id;

    for (int j = i * RATIO; j < i * RATIO + RATIO; j++) {
        if (esca_unlikely(ESCA_READ_ONCE(sq[j]->flags) & MAIN_WORKER_NEED_WAKEUP)) {
            sq[j]->flags |= START_WAKEUP_MAIN_WORKER;
            syscall(__NR_esca_wakeup, j);
            sq[j]->flags &= ~START_WAKEUP_MAIN_WORKER;
        }
    }
}

long batch_flush_and_wait_some(int num)
{
    int ret = syscall(__NR_esca_wait, this_worker_id, num);
    batch_num = 0;
    return ret;
}

long batch_flush()
{
    return batch_flush_and_wait_some(-1);
}

void toggle_region()
{
    in_segment ^= 1;
}

void update_tail(esca_table_t* T)
{
    // avoid overwriting;
    // FIXME: need to consider more -> cross table scenario
    // FIXME: order of the head might be protected by barrier

    while ((T->tail_entry + 1 == T->head_entry) && (T->tail_table == T->head_table))
        ;

    if (T->tail_entry == MAX_TABLE_ENTRY - 1) {
        T->tail_entry = 0;
        T->tail_table = (T->tail_table == MAX_TABLE_LEN - 1) ? 0 : T->tail_table + 1;
    } else {
        T->tail_entry++;
    }
}

void update_head(int* i, int* j)
{
    esca_table_t* T = cq[this_worker_id];

    // caller need to guarantee that there is available cqe
    if (*j == MAX_TABLE_ENTRY - 1) {
        *j = 0;
        *i = (*i == MAX_TABLE_LEN - 1) ? 0 : *i + 1;
    } else {
        *j += 1;
    }
}

esca_table_entry_t* get_cqe(int i, int j)
{
    esca_table_entry_t* res = &cq[this_worker_id]->user_tables[i][j];

    while (esca_smp_load_acquire(&res->rstatus) == BENTRY_EMPTY)
        ;

    res->rstatus = BENTRY_EMPTY;

    return res;
}

#include "redis.c"

void init_config(esca_config_t* c)
{
    ESCA_LOCALIZE = c->esca_localize;
    MAX_TABLE_ENTRY = c->max_table_entry;
    MAX_TABLE_LEN = c->max_table_len;
    MAX_USR_WORKER = c->max_usr_worker;
    MAX_CPU_NUM = c->max_ker_worker;
    RATIO = (MAX_CPU_NUM / MAX_USR_WORKER);
    DEFAULT_MAIN_IDLE_TIME = c->default_main_worker_idle_time;
    DEFAULT_WQ_IDLE_TIME = c->default_wq_worker_idle_time;
    AFF_OFF = c->affinity_offset;

    printf("\033[0;33m");
    printf(" Localize: \033[0;37m%s\033[0;33m\n", ESCA_LOCALIZE ? "Enable" : "Disable");
    printf(" MAX_TABLE_ENTRY: \033[0;37m%d\033[0;33m\n", MAX_TABLE_ENTRY);
    printf(" MAX_TABLE_LEN: \033[0;37m%d\033[0;33m\n", MAX_TABLE_LEN);
    printf(" MAX_USR_WORKER: \033[0;37m%d\033[0;33m\n", MAX_USR_WORKER);
    printf(" MAX_KER_WORKER: \033[0;37m%d\033[0;33m\n", MAX_CPU_NUM);
    printf(" AFF_OFF: \033[0;37m%d\033[0;33m\n", AFF_OFF);

    if (ESCA_LOCALIZE)
        printf(" # of K-worker per CPU: \033[0;37m%d\n", RATIO);
    printf("\033[0m");
}

//__attribute__((constructor))
void fastio_user_setup(void)
{
    FILE* fp;
    main_pid = getpid();
    pgsize = getpagesize();

    /* store glibc function */
    real_open = real_open ? real_open : dlsym(RTLD_NEXT, "open");
    real_close = real_close ? real_close : dlsym(RTLD_NEXT, "close");
    real_write = real_write ? real_write : dlsym(RTLD_NEXT, "write");
    real_read = real_read ? real_read : dlsym(RTLD_NEXT, "read");
    real_writev = real_writev ? real_writev : dlsym(RTLD_NEXT, "writev");
    real_shutdown = real_shutdown ? real_shutdown : dlsym(RTLD_NEXT, "shutdown");
    real_sendfile = real_sendfile ? real_sendfile : dlsym(RTLD_NEXT, "sendfile");
    real_sendmsg = real_sendmsg ? real_sendmsg : dlsym(RTLD_NEXT, "sendmsg");
    real_send = real_send ? real_send : dlsym(RTLD_NEXT, "send");
    real_accept4 = real_accept4 ? real_accept4 : dlsym(RTLD_NEXT, "accept4");

    /* configuration */
    config = malloc(sizeof(esca_config_t));

    fp = fopen(DEFAULT_CONFIG_PATH, "r+");
    if (!fp) {
        printf("\033[0;31mCould not open configuration file: %s\n\033[0mUsing default configuration ...\n", DEFAULT_CONFIG_PATH);
        config = &default_config;
    } else {
        while (1) {
            config_option_t option;
            if (fscanf(fp, "%s = %d", option.key, &option.val) != 2) {
                if (feof(fp)) {
                    break;
                }
                printf("Invalid format in config file\n");
                continue;
            }
            if (strcmp(option.key, "esca_localize") == 0) {
                config->esca_localize = option.val;
            } else if (strcmp(option.key, "max_table_entry") == 0) {
                config->max_table_entry = option.val;
            } else if (strcmp(option.key, "max_table_len") == 0) {
                config->max_table_len = option.val;
            } else if (strcmp(option.key, "max_usr_worker") == 0) {
                config->max_usr_worker = option.val;
            } else if (strcmp(option.key, "max_ker_worker") == 0) {
                config->max_ker_worker = option.val;
            } else if (strcmp(option.key, "default_main_worker_idle_time") == 0) {
                config->default_main_worker_idle_time = option.val;
            } else if (strcmp(option.key, "default_wq_worker_idle_time") == 0) {
                config->default_wq_worker_idle_time = option.val;
            } else if (strcmp(option.key, "affinity_offset") == 0) {
                config->affinity_offset = option.val;
            } else {
                printf("Invalid option: %s\n", option.key);
            }
        }
    }
    init_config(config);
    syscall(__NR_esca_config, config);
}
