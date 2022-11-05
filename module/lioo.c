#include <generated/asm-offsets.h> /* __NR_syscall_max */
#include <linux/anon_inodes.h>
#include <linux/blkdev.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h> /* kallsyms_lookup_name, __NR_* */
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h> /* copy_from_user put_user */
#include <linux/version.h>
#include <linux/wait.h>

#include "include/symbol.h"
#include "include/systab.h"
#include "include/util.h"
#include "lioo.h"
#include "syscall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Cheng");
MODULE_DESCRIPTION("Linux IO offloading");
MODULE_VERSION("0.1");

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

/* restore original syscall for recover */
void* syscall_register_ori;
void* syscall_exit_ori;
void* syscall_wait_ori;
void* syscall_init_conf_ori;

typedef asmlinkage long (*sys_call_ptr_t)(long);

int main_pid; /* PID of main thread */

/* declare shared table */
struct page* table_pinned_pages[CPU_NUM_LIMIT][TABLE_LEN_LIMIT];
struct page* shared_info_pinned_pages[1];
esca_table_t* table[CPU_NUM_LIMIT];

/* args for creating io_thread */
esca_wkr_args_t* wq_wrk_args[WORKQUEUE_DEFAULT_THREAD_NUMS];

short should_be_submitted[CPU_NUM_LIMIT];

static int worker(void* arg);

// TODO: encapsulate them
wait_queue_head_t wq_worker_wq[WORKQUEUE_DEFAULT_THREAD_NUMS];
wait_queue_head_t wq_worker_wait[WORKQUEUE_DEFAULT_THREAD_NUMS];
wait_queue_head_t worker_wait[CPU_NUM_LIMIT];
wait_queue_head_t wq[CPU_NUM_LIMIT];
// int flags[MAX_CPU_NUM]; // need_wake_up; this might be shared with user space (be aware of memory barrier)

typedef asmlinkage long (*F0_t)(void);
typedef asmlinkage long (*F1_t)(long);
typedef asmlinkage long (*F2_t)(long, long);
typedef asmlinkage long (*F3_t)(long, long, long);
typedef asmlinkage long (*F4_t)(long, long, long, long);
typedef asmlinkage long (*F5_t)(long, long, long, long, long);
typedef asmlinkage long (*F6_t)(long, long, long, long, long, long);

static struct task_struct* worker_task[CPU_NUM_LIMIT];

// void (*wake_up_new_task_ptr)(struct task_struct *) = 0;

static inline long
indirect_call(void* f, int argc,
    long* a)
{
    struct pt_regs regs;
    memset(&regs, 0, sizeof regs);
    switch (argc) {
#if defined(__x86_64__)
    case 6:
        regs.r9 = a[5];
    case 5:
        regs.r8 = a[4];
    case 4:
        regs.r10 = a[3];
    case 3:
        regs.dx = a[2];
    case 2:
        regs.si = a[1];
    case 1:
        regs.di = a[0];
#elif defined(__aarch64__)
    case 6:
        regs.regs[5] = a[5];
    case 5:
        regs.regs[4] = a[4];
    case 4:
        regs.regs[3] = a[3];
    case 3:
        regs.regs[2] = a[2];
    case 2:
        regs.regs[1] = a[1];
    case 1:
        regs.regs[0] = a[0];
#endif
    }
    return ((F1_t)f)((long)&regs);
}

#if defined(__aarch64__)

static struct mm_struct* init_mm_ptr;
// From arch/arm64/mm/pageattr.c.
struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};

// From arch/arm64/mm/pageattr.c.
static int change_page_range(pte_t* ptep, unsigned long addr, void* data)
{
    struct page_change_data* cdata = data;
    pte_t pte = READ_ONCE(*ptep);

    pte = clear_pte_bit(pte, cdata->clear_mask);
    pte = set_pte_bit(pte, cdata->set_mask);

    set_pte(ptep, pte);
    return 0;
}

// From arch/arm64/mm/pageattr.c.
static int __change_memory_common(unsigned long start, unsigned long size,
    pgprot_t set_mask, pgprot_t clear_mask)
{
    struct page_change_data data;
    int ret;

    data.set_mask = set_mask;
    data.clear_mask = clear_mask;

    ret = apply_to_page_range(init_mm_ptr, start, size, change_page_range, &data);

    flush_tlb_kernel_range(start, start + size);
    return ret;
}

// Simplified set_memory_rw() from arch/arm64/mm/pageattr.c.
static int set_page_rw(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE), __pgprot(PTE_RDONLY));
}

// Simplified set_memory_ro() from arch/arm64/mm/pageattr.c.
static int set_page_ro(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY), __pgprot(PTE_WRITE));
}

void allow_writes(void)
{
    set_page_rw((unsigned long)(syscall_table_ptr + __NR_esca_register) & PAGE_MASK);
}
void disallow_writes(void)
{
    set_page_ro((unsigned long)(syscall_table_ptr + __NR_esca_register) & PAGE_MASK);
}
static void enable_cycle_counter_el0(void* data)
{
    u64 val;
    /* Disable cycle counter overflow interrupt */
    asm volatile("msr pmintenset_el1, %0"
                 :
                 : "r"((u64)(0 << 31)));
    /* Enable cycle counter */
    asm volatile("msr pmcntenset_el0, %0" ::"r" BIT(31));
    /* Enable user-mode access to cycle counters. */
    asm volatile("msr pmuserenr_el0, %0"
                 :
                 : "r"(BIT(0) | BIT(2)));
    /* Clear cycle counter and start */
    asm volatile("mrs %0, pmcr_el0"
                 : "=r"(val));
    val |= (BIT(0) | BIT(2));
    isb();
    asm volatile("msr pmcr_el0, %0"
                 :
                 : "r"(val));
    val = BIT(27);
    asm volatile("msr pmccfiltr_el0, %0"
                 :
                 : "r"(val));
}

static void disable_cycle_counter_el0(void* data)
{
    /* Disable cycle counter */
    asm volatile("msr pmcntenset_el0, %0" ::"r"(0 << 31));
    /* Disable user-mode access to counters. */
    asm volatile("msr pmuserenr_el0, %0"
                 :
                 : "r"((u64)0));
}
#endif

static void copy_table_entry_and_advance(int ctx_idx, int wrk_idx, esca_table_entry_t* ent)
{
    int tail = ctx[ctx_idx]->df_tail[wrk_idx];
    esca_table_entry_t* dst = &ctx[ctx_idx]->deferred_list[wrk_idx][tail];

    dst->nargs = ent->nargs;
    dst->sysnum = ent->sysnum;

    for (int i = 0; i < 6; i++)
        dst->args[i] = ent->args[i];

    ctx[ctx_idx]->df_tail[wrk_idx] = (ctx[ctx_idx]->df_tail[wrk_idx] + 1) & ctx[ctx_idx]->df_mask;
    ent->rstatus = BENTRY_EMPTY;
    smp_store_release(&dst->rstatus, BENTRY_BUSY);
}

static int main_worker(void* arg)
{
    allow_signal(SIGKILL);
    int offloaded, res;
    int cur_cpuid = ((esca_wkr_args_t*)arg)->ctx_id;
    unsigned long timeout = 0;

    if (ESCA_LOCALIZE)
        set_cpus_allowed_ptr(current, cpumask_of(cur_cpuid / RATIO) + AFF_OFF);
    else
        set_cpus_allowed_ptr(current, cpumask_of(cur_cpuid) + AFF_OFF);

    printk("In main-worker, pid = %d, bound at cpu %d, cur_cpupid = %d\n",
        current->pid, smp_processor_id(), cur_cpuid);

    init_waitqueue_head(&wq[cur_cpuid]);
    DEFINE_WAIT(wait);

    while (1) {
        int i = table[cur_cpuid]->head_table;
        int j = table[cur_cpuid]->head_entry;
        int head_index, tail_index;

        while (smp_load_acquire(&table[cur_cpuid]->tables[i][j].rstatus) == BENTRY_EMPTY) {
            if (signal_pending(current)) {
                printk("detect signal\n");
                goto main_worker_exit;
            }
            // FIXME:
            if (!time_after(jiffies, timeout)) {
                // still don't need to sleep
                cond_resched();
                continue;
            }

            prepare_to_wait(&worker_wait[cur_cpuid], &wait, TASK_INTERRUPTIBLE);
            WRITE_ONCE(table[cur_cpuid]->flags, table[cur_cpuid]->flags | ESCA_WORKER_NEED_WAKEUP);

            if (smp_load_acquire(&table[cur_cpuid]->tables[i][j].rstatus) == BENTRY_EMPTY) {
                schedule();
                // wake up by `wake_up` in batch_start
                finish_wait(&worker_wait[cur_cpuid], &wait);

                // clear need_wakeup
                // FIXME: // need write barrier?
                WRITE_ONCE(table[cur_cpuid]->flags, table[cur_cpuid]->flags & ~ESCA_WORKER_NEED_WAKEUP);
                timeout = jiffies + table[cur_cpuid]->idle_time;
                continue;
            }

            // condition satisfied, don't schedule
            finish_wait(&worker_wait[cur_cpuid], &wait);
            WRITE_ONCE(table[cur_cpuid]->flags, table[cur_cpuid]->flags & ~ESCA_WORKER_NEED_WAKEUP);
        }

        head_index = (i * MAX_TABLE_ENTRY) + j;
        tail_index = (table[cur_cpuid]->tail_table * MAX_TABLE_ENTRY) + table[cur_cpuid]->tail_entry;
        should_be_submitted[cur_cpuid] = (tail_index >= head_index)
            ? tail_index - head_index
            : MAX_TABLE_ENTRY * MAX_TABLE_LEN - head_index + tail_index;
        offloaded = 0;

        while (should_be_submitted[cur_cpuid] != 0) {
            esca_table_entry_t* ent = &table[cur_cpuid]->tables[i][j];

            // res = indirect_call(syscall_table_ptr[ent->sysnum], ent->nargs, ent->args);

            if (1) { // res == -EAGAIN) {

                // TODO: choose arg. depending on syscall
                int hash = ent->args[0] & (WORKQUEUE_DEFAULT_THREAD_NUMS - 1);
                offloaded++;

                copy_table_entry_and_advance(cur_cpuid, hash, ent);

                if (smp_load_acquire(&work_node_reg[hash]->status) == IDLE) {

                    spin_lock_irq(&ctx[cur_cpuid]->l_lock);

                    // remove current node in free list
                    list_del(&work_node_reg[hash]->list);

                    // append current node to the tail of running list
                    list_add_tail(&work_node_reg[hash]->list, &ctx[cur_cpuid]->running_list->list);

                    ctx[cur_cpuid]->free_list->len--;
                    ctx[cur_cpuid]->running_list->len++;
                    spin_unlock_irq(&ctx[cur_cpuid]->l_lock);

                    wake_up(&wq_worker_wq[hash]);
                }
            } else {
                // TODO: push result to completion queue
                ent->sysret = res;
#if 1
                printk(KERN_INFO "Index %d,%d do syscall %d : %d = (%d, %d, %ld, %d) at cpu%d\n", i, j,
                    ent->sysnum, ent->sysret, ent->args[0], ent->args[1], ent->args[2], ent->args[3], smp_processor_id());
#endif
            }

            // FIXME: need barrier?
            ent->rstatus = BENTRY_EMPTY;
            should_be_submitted[cur_cpuid]--;

            if (j == MAX_TABLE_ENTRY - 1) {
                i = (i == MAX_TABLE_LEN - 1) ? 0 : i + 1;
                j = 0;
            } else {
                j++;
            }

            short done = 1;
            if (cur_cpuid % RATIO == 0) {
                for (int k = cur_cpuid; k < cur_cpuid + RATIO; k++) {
                    if (should_be_submitted[k] != 0) {
                        done = 0;
                        break;
                    }
                }
                if (done == 1) {
                    // FIXME: try to use the logic `ctx[cur_cpuid]->comp_num != offloaded`
                    while (list_empty(&ctx[cur_cpuid]->running_list->list)) {
                        cond_resched();
                    }

                    wake_up_interruptible(&wq[cur_cpuid]);
                }
            }

            timeout = jiffies + table[cur_cpuid]->idle_time;
        }
        cond_resched();
        table[cur_cpuid]->head_table = i;
        table[cur_cpuid]->head_entry = j;

        if (signal_pending(current)) {
            printk("detect signal from main_worker\n");
            goto main_worker_exit;
        }
    }

main_worker_exit:
    printk("main_worker exit\n");
    do_exit(0);
    return 0;
}

static int wq_worker(void* arg)
{
    allow_signal(SIGKILL);

    int ret = 0, head;
    int ctx_id = ((esca_wkr_args_t*)arg)->ctx_id;
    int wq_wrk_id = ((esca_wkr_args_t*)arg)->wq_wrk_id;
    unsigned long timeout = 0;

    DEFINE_WAIT(wq_wait);
    init_waitqueue_head(&wq_worker_wq[wq_wrk_id]);

    esca_table_entry_t* ent;
    struct list_head* self = ((esca_wkr_args_t*)arg)->self;

    // TODO: set affinity
    printk("wq-%d is launching, running on CPU-%d\n", wq_wrk_id, smp_processor_id());

    while (1) {
    wq_worker_advance:
        head = ctx[ctx_id]->df_head[wq_wrk_id];
        ent = &ctx[ctx_id]->deferred_list[wq_wrk_id][head];

        while (smp_load_acquire(&ent->rstatus) == BENTRY_EMPTY) {
            // hybrid (busy waiting + sleep & wait)
            if (signal_pending(current)) {
                printk("detect signal from wq_worker\n");
                goto wq_worker_exit;
            }

            // force to sleep in first-entrance
            if (!time_after(jiffies, timeout)) {
                cond_resched();
                continue;
            }

            goto wq_worker_sleep;
        }

        // update indexing

        do {
            ret = indirect_call(syscall_table_ptr[ent->sysnum], ent->nargs, ent->args);

#if 0
            printk(KERN_INFO "In wq-%d, do syscall %d : %d = (%d, %d, %ld, %d) at cpu%d\n", wq_wrk_id,
                ent->sysnum, ret, ent->args[0], ent->args[1], ent->args[2], ent->args[3], smp_processor_id());
#endif

            if (ret != -EAGAIN)
                break;
            cond_resched();
        } while (1);

        ctx[ctx_id]->df_head[wq_wrk_id] = (head + 1) & ctx[ctx_id]->df_mask;

        // TODO: push result to completion queue
        ent->sysret = ret;
        work_node_reg[wq_wrk_id]->cache_comp_num++;
        ent->rstatus = BENTRY_EMPTY;

        timeout = jiffies + ctx[ctx_id]->idle_time;
        goto wq_worker_advance;

    wq_worker_sleep:
        printk("wq-%d go to sleep\n", wq_wrk_id);
        spin_lock_irq(&ctx[ctx_id]->l_lock);

        // remove current node in running list
        list_del(self);

        // append current node to the tail of free list
        list_add_tail(self, &ctx[ctx_id]->free_list->list);

        ctx[ctx_id]->free_list->len++;
        ctx[ctx_id]->running_list->len--;

        spin_unlock_irq(&ctx[ctx_id]->l_lock);

        prepare_to_wait(&wq_worker_wq[wq_wrk_id], &wq_wait, TASK_INTERRUPTIBLE);

        smp_store_release(&work_node_reg[wq_wrk_id]->status, IDLE);
        spin_lock_irq(&ctx[ctx_id]->comp_lock);
        printk("in wq-%d, comp_num=%d\n", wq_wrk_id, ctx[ctx_id]->comp_num);
        spin_unlock_irq(&ctx[ctx_id]->comp_lock);
        schedule();

        // wake up by main_worker
        printk("wq-%d is waken up\n", wq_wrk_id); // FIXME: remove later
        work_node_reg[wq_wrk_id]->status = RUNNING;
        timeout = jiffies + ctx[ctx_id]->idle_time;
        finish_wait(&wq_worker_wq[wq_wrk_id], &wq_wait);

        if (signal_pending(current)) {
            printk("detect signal from wq_worker\n");
            goto wq_worker_exit;
        }
    }

wq_worker_exit:
    printk("wq_worker exit\n");
    do_exit(0);
    return 0;
}

/* after linux kernel 4.7, parameter was restricted into pt_regs type */
asmlinkage long sys_esca_register(const struct __user pt_regs* regs)
{
    // regs should contain: header, user_tables, id, set_index
#if defined(__x86_64__)
    unsigned long p1[4] = { regs->di, regs->si, regs->dx, regs->r10 };
#elif defined(__aarch64__)
    unsigned long p1[4] = { regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3] };
#endif

    // FIXME: check if p1[0] is needed
    struct file* file;
    int n_page, id = p1[2], fd, set_index = p1[3];

    // FIXME: release
    esca_wkr_args_t* main_wrk_args = (esca_wkr_args_t*)kmalloc(sizeof(esca_wkr_args_t), GFP_KERNEL);
    main_wrk_args->ctx_id = id;

    if (p1[0]) {
        /* header is not null */
        n_page = get_user_pages((unsigned long)(p1[0]), 1, FOLL_FORCE | FOLL_WRITE,
            shared_info_pinned_pages, NULL);

        esca_table_t* header = (esca_table_t*)kmap(shared_info_pinned_pages[0]);
        for (int i = id; i < id + RATIO; i++) {
            table[i] = header + i - id;
        }
    } else {
        /* make sure header has been register */
        while (!table[id]) {
            cond_resched();
        }
    }

    /* map tables from user-space to kernel */
    n_page = get_user_pages((unsigned long)(p1[1]), MAX_TABLE_LEN,
        FOLL_FORCE | FOLL_WRITE, table_pinned_pages[id],
        NULL);
    printk("Pin %d pages in worker %d\n", n_page, id);

    for (int j = 0; j < MAX_TABLE_LEN; j++) {
        table[id]->tables[j] = (esca_table_entry_t*)kmap(table_pinned_pages[id][j]);
        printk("table[%d][%d]=%p\n", id, j, table[id]->tables[j]);
    }

    /* initial entry status */
    for (int j = 0; j < MAX_TABLE_LEN; j++)
        for (int k = 0; k < MAX_TABLE_ENTRY; k++)
            table[id]->tables[j][k].rstatus = BENTRY_EMPTY;

    for (int i = 0; i < CPU_NUM_LIMIT; i++) {
        worker_task[i] = NULL;
    }

    // TODO: merge them
    table[id]->head_table = table[id]->tail_table = 0;
    table[id]->head_entry = table[id]->tail_entry = 0;

    // TODO: merge them
    should_be_submitted[id] = 0;
    table[id]->flags = 0 | ESCA_WORKER_NEED_WAKEUP;
    table[id]->idle_time = msecs_to_jiffies(DEFAULT_MAIN_IDLE_TIME);
    init_waitqueue_head(&worker_wait[id]);

    // setup main offloading-thread
    worker_task[id] = create_io_thread_ptr(main_worker, main_wrk_args, -1);

    // setup context of fastio

    ctx[id] = kmalloc(sizeof(struct fastio_ctx), GFP_KERNEL);
    ctx[id]->running_list = ctx[id]->free_list = NULL;
    ctx[id]->df_mask = MAX_DEFERRED_NUM - 1;
    ctx[id]->comp_num = 0;
    ctx[id]->idle_time = msecs_to_jiffies(DEFAULT_WQ_IDLE_TIME);

    for (int i = 0; i < WORKQUEUE_DEFAULT_THREAD_NUMS; i++) {
        ctx[id]->df_head[i] = ctx[id]->df_tail[i] = 0;
        init_waitqueue_head(&wq_worker_wait[i]);

        for (int j = 0; j < MAX_DEFERRED_NUM; j++) {
            ctx[id]->deferred_list[i][j].rstatus = BENTRY_EMPTY;
        }
    }

    spin_lock_init(&ctx[id]->l_lock);
    spin_lock_init(&ctx[id]->df_lock);
    spin_lock_init(&ctx[id]->comp_lock);

    create_worker_pool(WORKQUEUE_DEFAULT_THREAD_NUMS, id);

    wake_up_new_task_ptr(worker_task[id]);

    for (int i = 0; i < WORKQUEUE_DEFAULT_THREAD_NUMS; i++)
        wake_up_new_task_ptr(work_node_reg[i]->task);

    return 0;
}

static void create_worker_pool(int concurrency, int ctx_id)
{
    struct fastio_work_meta* rhead = kmalloc(sizeof(struct fastio_work_meta), GFP_KERNEL);
    struct fastio_work_meta* fhead = kmalloc(sizeof(struct fastio_work_meta), GFP_KERNEL);

    INIT_LIST_HEAD(&rhead->list);
    INIT_LIST_HEAD(&fhead->list);

    rhead->len = fhead->len = 0;

    ctx[ctx_id]->running_list = rhead;
    ctx[ctx_id]->free_list = fhead;

    for (int arg_idx = 0; arg_idx < concurrency; arg_idx++) {
        struct fastio_work_node* node = kmalloc(sizeof(struct fastio_work_node), GFP_KERNEL);

        work_node_reg[arg_idx] = node;

        wq_wrk_args[arg_idx] = (esca_wkr_args_t*)kmalloc(sizeof(esca_wkr_args_t), GFP_KERNEL);
        wq_wrk_args[arg_idx]->ctx_id = ctx_id;
        wq_wrk_args[arg_idx]->wq_wrk_id = arg_idx;
        wq_wrk_args[arg_idx]->self = &node->list;

        node->status = IDLE;
        node->cache_comp_num = 0;
        node->task = create_io_thread_ptr(wq_worker, wq_wrk_args[arg_idx], -1);
        spin_lock_init(&node->wrk_lock);
        list_add_tail(&node->list, &ctx[ctx_id]->running_list->list);
        ctx[ctx_id]->free_list->len++;
    }
}

asmlinkage void sys_lioo_exit(void)
{
    printk(KERN_INFO "syscall exit\n");
    for (int i = 0; i < MAX_CPU_NUM; i++) {
        if (worker_task[i])
            kthread_stop(worker_task[i]);
        worker_task[i] = NULL;
    }
}

asmlinkage void sys_esca_wakeup(const struct __user pt_regs* regs)
{
#if defined(__x86_64__)
    int i = regs->di;
#elif defined(__aarch64__)
    int i = regs->regs[0];
#endif

    if (likely(READ_ONCE(table[i]->flags) & ESCA_START_WAKEUP)) {
        wake_up(&worker_wait[i]);
    }
}

asmlinkage void sys_esca_wait(const struct __user pt_regs* regs)
{
#if defined(__x86_64__)
    int idx = regs->di;
#elif defined(__aarch64__)
    int idx = regs->regs[0];
#endif
    wait_event_interruptible(wq[idx], 1);
}

asmlinkage void sys_esca_init_config(const struct __user pt_regs* regs)
{
#if defined(__x86_64__)
    void* ptr = regs->di;
#elif defined(__aarch64__)
    void* ptr = regs->regs[0];
#endif
    esca_config_t* kconfig = kmalloc(sizeof(esca_config_t), GFP_KERNEL);

    if (!kconfig) {
        printk("[ERROR] Fail at configuring\n");
    }

    copy_from_user(kconfig, ptr, sizeof(esca_config_t));

    ESCA_LOCALIZE = kconfig->esca_localize;
    MAX_TABLE_ENTRY = kconfig->max_table_entry;
    MAX_TABLE_LEN = kconfig->max_table_len;
    MAX_USR_WORKER = kconfig->max_usr_worker;
    MAX_CPU_NUM = kconfig->max_ker_worker;
    RATIO = (MAX_CPU_NUM / MAX_USR_WORKER);
    DEFAULT_MAIN_IDLE_TIME = kconfig->default_main_worker_idle_time;
    DEFAULT_WQ_IDLE_TIME = kconfig->default_wq_worker_idle_time;
    AFF_OFF = kconfig->affinity_offset;

    printk("Localize: %s\n", ESCA_LOCALIZE ? "Enable" : "Disable");
    printk("MAX_TABLE_ENTRY: %d\n", MAX_TABLE_ENTRY);
    printk("MAX_TABLE_LEN: %d\n", MAX_TABLE_LEN);
    printk("MAX_USR_WORKER: %d\n", MAX_USR_WORKER);
    printk("MAX_KER_WORKER: %d\n", MAX_CPU_NUM);
    printk("AFF_OFF: %d\n", AFF_OFF);

    if (ESCA_LOCALIZE)
        printk("# of K-worker per CPU: %d\n", RATIO);
}

static int __init lioo_init(void)
{

    init_not_exported_symbol();

#if defined(__aarch64__)
    init_mm_ptr = (struct mm_struct*)(sysMM + ((char*)&system_wq - sysWQ));
    on_each_cpu(enable_cycle_counter_el0, NULL, 1);
#endif

    /* allow write */
    allow_writes();
    /* backup */
    syscall_register_ori = (void*)syscall_table_ptr[__NR_esca_register];
    syscall_exit_ori = (void*)syscall_table_ptr[__NR_esca_wakeup];
    syscall_wait_ori = (void*)syscall_table_ptr[__NR_esca_wait];
    syscall_init_conf_ori = (void*)syscall_table_ptr[__NR_esca_config];

    /* hooking */
    syscall_table_ptr[__NR_esca_register] = (void*)sys_esca_register;
    syscall_table_ptr[__NR_esca_wakeup] = (void*)sys_esca_wakeup;
    syscall_table_ptr[__NR_esca_wait] = (void*)sys_esca_wait;
    syscall_table_ptr[__NR_esca_config] = (void*)sys_esca_init_config;

    /* dis-allow write */
    disallow_writes();

    printk("lioo init\n");
    return 0;
}
static void __exit lioo_exit(void)
{
    /* recover */
    allow_writes();
    syscall_table_ptr[__NR_esca_register] = (void*)syscall_register_ori;
    syscall_table_ptr[__NR_esca_wakeup] = (void*)syscall_exit_ori;
    syscall_table_ptr[__NR_esca_wait] = (void*)syscall_wait_ori;
    syscall_table_ptr[__NR_esca_config] = (void*)syscall_init_conf_ori;
    disallow_writes();

#if defined(__aarch64__)
    init_mm_ptr = (struct mm_struct*)(sysMM + ((char*)&system_wq - sysWQ));
    on_each_cpu(disable_cycle_counter_el0, NULL, 1);
#endif

    // kfree(main_wrk_args);
    // for (int i = 0; i < WORKQUEUE_DEFAULT_THREAD_NUMS; i++)
    //     kfree(wq_wrk_args[i]);
    //  if(worker_task)
    //   kthread_stop(worker_task);

    printk("lioo exit\n");
}
module_init(lioo_init);
module_exit(lioo_exit);
