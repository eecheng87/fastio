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
#include <linux/sched.h>
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
int WQ_AFF_OFF;

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

esca_table_t* sq[CPU_NUM_LIMIT];
esca_table_t* cq[CPU_NUM_LIMIT];

/* args for creating io_thread */
esca_wkr_args_t* wq_wrk_args[WORKQUEUE_DEFAULT_THREAD_NUMS];

short should_be_submitted[CPU_NUM_LIMIT];

static int worker(void* arg);

// TODO: encapsulate them
wait_queue_head_t wq_worker_wq[WORKQUEUE_DEFAULT_THREAD_NUMS];
wait_queue_head_t wq_worker_wait[WORKQUEUE_DEFAULT_THREAD_NUMS];
wait_queue_head_t main_worker_wait[CPU_NUM_LIMIT];
wait_queue_head_t wq[CPU_NUM_LIMIT];
// int flags[MAX_CPU_NUM]; // need_wake_up; this might be shared with user space (be aware of memory barrier)

// TODO: encapsulate them
int mini_ret = 1; // for `batch_flush_and_wait_some`

typedef asmlinkage long (*F0_t)(void);
typedef asmlinkage long (*F1_t)(long);
typedef asmlinkage long (*F2_t)(long, long);
typedef asmlinkage long (*F3_t)(long, long, long);
typedef asmlinkage long (*F4_t)(long, long, long, long);
typedef asmlinkage long (*F5_t)(long, long, long, long, long);
typedef asmlinkage long (*F6_t)(long, long, long, long, long, long);

static struct task_struct* worker_task[CPU_NUM_LIMIT];

static inline int get_nxt_wq(int idx)
{
    int res;
    do {
        res = ctx[idx]->nxt_wq;
        ctx[idx]->nxt_wq = (ctx[idx]->nxt_wq + 1) & 31;
    } while ((~READ_ONCE(ctx[idx]->wq_status)) & (1 << res));

    return res;
}

static inline int is_master(int idx)
{
    return (idx % RATIO == 0) ? 1 : 0;
}

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

static void fill_cqe(int ctx_id, esca_table_entry_t* ent)
{
    int cq_i, cq_j;
    esca_table_entry_t* dest;

    spin_lock_irq(&ctx[ctx_id]->cq_lock);
    cq_i = cq[ctx_id]->tail_table;
    cq_j = cq[ctx_id]->tail_entry;

    dest = &cq[ctx_id]->tables[cq_i][cq_j];

    if (cq_j == MAX_TABLE_ENTRY - 1) {
        cq_i = (cq_i == MAX_TABLE_LEN - 1) ? 0 : cq_i + 1;
        cq_j = 0;
    } else {
        cq_j++;
    }

    cq[ctx_id]->tail_table = cq_i;
    cq[ctx_id]->tail_entry = cq_j;

    spin_unlock_irq(&ctx[ctx_id]->cq_lock);

    dest->sysret = ent->sysret;
    dest->sysnum = ent->sysnum;

    for (int i = 0; i < 3; i++)
        dest->args[i] = ent->args[i];

    smp_store_release(&dest->rstatus, BENTRY_BUSY);
}

static void copy_table_entry_and_advance(int ctx_idx, int wrk_idx, int main_id, esca_table_entry_t* ent)
{
    int tail;
    esca_table_entry_t* dst;

    // protected: accessed by multiple main-worker
    spin_lock_irq(&ctx[ctx_idx]->df_lock);
    tail = ctx[ctx_idx]->df_tail[wrk_idx];
    ctx[ctx_idx]->df_tail[wrk_idx] = (ctx[ctx_idx]->df_tail[wrk_idx] + 1) & ctx[ctx_idx]->df_mask;
    spin_unlock_irq(&ctx[ctx_idx]->df_lock);

    dst = &ctx[ctx_idx]->deferred_list[wrk_idx][tail];

    dst->nargs = ent->nargs;
    dst->sysnum = ent->sysnum;

    for (int i = 0; i < 6; i++)
        dst->args[i] = ent->args[i];

    /* store id of main_worker who dispatch this task */
    dst->pid = main_id;

    smp_store_release(&dst->rstatus, BENTRY_BUSY);
}

static void move_deferred_entry(int ctx_idx, int wrk_idx, int src_idx, int dst_idx)
{
    esca_table_entry_t* src = &ctx[ctx_idx]->deferred_list[wrk_idx][src_idx];
    esca_table_entry_t* dst = &ctx[ctx_idx]->deferred_list[wrk_idx][dst_idx];

    dst->nargs = src->nargs;
    dst->sysnum = src->sysnum;

    for (int i = 0; i < 6; i++)
        dst->args[i] = src->args[i];

    dst->rstatus = BENTRY_BUSY;
    src->rstatus = BENTRY_EMPTY;
}

// don't use this function, not safe
static int get_ready_qlen(esca_table_t* T, int id)
{
    int head_index, tail_index;

    head_index = (T->head_table * MAX_TABLE_ENTRY) + T->head_entry;

    // accessing `tail_index` needs a lock
    tail_index = (T->tail_table * MAX_TABLE_ENTRY) + T->tail_entry;

    return (tail_index >= head_index) ? tail_index - head_index : MAX_TABLE_ENTRY * MAX_TABLE_LEN - head_index + tail_index;
}

static int get_ready_qlen_and_advance(esca_table_t* T, int id)
{
    int head_index, tail_index;

    head_index = (T->head_table * MAX_TABLE_ENTRY) + T->head_entry;

    spin_lock_irq(&ctx[id]->cq_lock);
    tail_index = (T->tail_table * MAX_TABLE_ENTRY) + T->tail_entry;

    T->head_table = T->tail_table;
    T->head_entry = T->tail_entry;
    spin_unlock_irq(&ctx[id]->cq_lock);

    return (tail_index >= head_index) ? tail_index - head_index : MAX_TABLE_ENTRY * MAX_TABLE_LEN - head_index + tail_index;
}

static int main_worker(void* arg)
{
    allow_signal(SIGKILL);

    int offloaded = 0, res;
    int ctx_id = ((esca_wkr_args_t*)arg)->ctx_id;
    int wrk_id = ((esca_wkr_args_t*)arg)->wrk_id;
    int master_id = ctx_id;

    unsigned long timeout = jiffies + sq[wrk_id]->idle_time;

    if (ESCA_LOCALIZE)
        set_cpus_allowed_ptr(current, cpumask_of(ctx_id) + AFF_OFF);
    else
        set_cpus_allowed_ptr(current, cpumask_of(wrk_id) + AFF_OFF);

    printk("In main-worker, pid = %d, bound at cpu %d, cur_cpupid = %d\n",
        current->pid, smp_processor_id(), ESCA_LOCALIZE ? ctx_id : wrk_id);

    DEFINE_WAIT(wait);

    while (1) {
        int i = sq[wrk_id]->head_table;
        int j = sq[wrk_id]->head_entry;

        while (smp_load_acquire(&sq[wrk_id]->tables[i][j].rstatus) == BENTRY_EMPTY) {
            if (signal_pending(current)) {
                printk("detect signal\n");
                goto main_worker_exit;
            }

            WRITE_ONCE(sq[wrk_id]->flags, sq[wrk_id]->flags | CTX_FLAGS_MAIN_WOULD_SLEEP);

            if (!time_after(jiffies, timeout)) {
                // master entering only
                if (is_master(wrk_id) && (READ_ONCE(sq[wrk_id]->wq_has_finished) != 0 || READ_ONCE(sq[wrk_id]->main_has_finished) != 0)) {
                    // FIXME: do we need lock to protect `wq_has_finished`?
                    sq[wrk_id]->main_has_finished = sq[wrk_id]->wq_has_finished = 0;
                    goto main_done_entry;
                }

                // still don't need to sleep
                smp_mb();
                cond_resched();
                continue;
            }

            prepare_to_wait(&main_worker_wait[wrk_id], &wait, TASK_INTERRUPTIBLE);
            WRITE_ONCE(sq[wrk_id]->flags, sq[wrk_id]->flags | MAIN_WORKER_NEED_WAKEUP);

            if (smp_load_acquire(&sq[wrk_id]->tables[i][j].rstatus) == BENTRY_EMPTY) {
                // printk("main-%d go to sleep\n", wrk_id);
                schedule();
                // wake up by `wake_up` in batch_start or wq_worker or slave-main_worker
                finish_wait(&main_worker_wait[wrk_id], &wait);
                // printk("main-%d is waken up\n", wrk_id);

                // clear need_wakeup
                // FIXME: need write barrier?
                WRITE_ONCE(sq[wrk_id]->flags, sq[wrk_id]->flags & ~MAIN_WORKER_NEED_WAKEUP);
                timeout = jiffies + sq[wrk_id]->idle_time;

                if (is_master(wrk_id) && (READ_ONCE(sq[wrk_id]->wq_has_finished) != 0 || READ_ONCE(sq[wrk_id]->main_has_finished) != 0)) {
                    // FIXME: do we need lock to protect `wq_has_finished`?
                    sq[wrk_id]->main_has_finished = sq[wrk_id]->wq_has_finished = 0;
                    goto main_done_entry;
                }

                continue;
            }

            // condition satisfied, don't schedule
            finish_wait(&main_worker_wait[wrk_id], &wait);
            WRITE_ONCE(sq[wrk_id]->flags, sq[wrk_id]->flags & ~MAIN_WORKER_NEED_WAKEUP);
        }
        WRITE_ONCE(sq[wrk_id]->flags, sq[wrk_id]->flags & ~CTX_FLAGS_MAIN_WOULD_SLEEP);

    submitted_again:

        while (smp_load_acquire(&sq[wrk_id]->tables[i][j].rstatus) != BENTRY_EMPTY) {
            esca_table_entry_t* ent = &sq[wrk_id]->tables[i][j];

            res = indirect_call(syscall_table_ptr[ent->sysnum], ent->nargs, ent->args);

            if (res == -EAGAIN) {
                // FIXME: refactor
                // one wq-worker only; always dispatch to wq-worker-0
                int nxt_wq = 0;

                copy_table_entry_and_advance(ctx_id, nxt_wq, wrk_id, ent);

                /*
                    The status of a deferred entry has become BUSY, from here
                */

                smp_mb();
                if (!(READ_ONCE(work_node_reg[nxt_wq]->status) & WQ_FLAGS_IS_RUNNING)) {
                    WRITE_ONCE(work_node_reg[nxt_wq]->status, work_node_reg[nxt_wq]->status | WQ_FLAGS_IS_RUNNING);
                    wake_up(&wq_worker_wq[nxt_wq]);
                }
            } else {
                offloaded++;
                ent->sysret = res;
                fill_cqe(ctx_id, ent);

                // FIXME: move out of this loop, and replacing with `ctx[ctx_id]->comp_num += offloaded`
                spin_lock_irq(&ctx[ctx_id]->comp_lock);
                ctx[ctx_id]->comp_num++;
                spin_unlock_irq(&ctx[ctx_id]->comp_lock);

#if 0
                printk(KERN_INFO "Index %d,%d do syscall %d : %d = (%d, %d, %ld, %d) at cpu%d\n", i, j,
                    ent->sysnum, res, ent->args[0], ent->args[1], ent->args[2], ent->args[3], smp_processor_id());
#endif
            }
            // FIXME: need barrier?
            smp_store_release(&ent->rstatus, BENTRY_EMPTY);

            if (j == MAX_TABLE_ENTRY - 1) {
                i = (i == MAX_TABLE_LEN - 1) ? 0 : i + 1;
                j = 0;
            } else {
                j++;
            }

            // master entering only
            if (wrk_id % RATIO == 0 && smp_load_acquire(&sq[wrk_id]->tables[i][j].rstatus) == BENTRY_EMPTY) {

            main_done_entry:
                // printk("main-%d entering main_done_entry\n", wrk_id);
                // FIXME: current implementation only considering the threshold always be 1
                while (ctx[ctx_id]->comp_num < 1) {
                    cond_resched();

                    if (smp_load_acquire(&sq[wrk_id]->tables[i][j].rstatus) != BENTRY_EMPTY)
                        goto submitted_again;

                    if (READ_ONCE(sq[wrk_id]->wq_has_finished) != 0 || READ_ONCE(sq[wrk_id]->main_has_finished) != 0) {
                        sq[wrk_id]->main_has_finished = sq[wrk_id]->wq_has_finished = 0;
                        break;
                    }

                    if (signal_pending(current))
                        goto main_worker_exit;
                }
                // printk("main-%d leaving main_done_entry\n", wrk_id);
                //    FIXME: is lock needed?
                spin_lock_irq(&ctx[ctx_id]->comp_lock);
                ctx[ctx_id]->comp_num = 0;
                spin_unlock_irq(&ctx[ctx_id]->comp_lock);

                WRITE_ONCE(ctx[ctx_id]->status, ctx[ctx_id]->status | CTX_FLAGS_MAIN_DONE);
                smp_mb(); // FIXME: is this needed?
                wake_up_interruptible(&wq[ctx_id]);
            }

            timeout = jiffies + sq[wrk_id]->idle_time;
        }

        if (offloaded > 0 && !is_master(wrk_id)) {
            // force master leaving empty loop
            sq[master_id]->main_has_finished |= ((unsigned int)1 << wrk_id);
            smp_mb();

            // do we need to wake up main-worker?
            if (READ_ONCE(sq[master_id]->flags) & MAIN_WORKER_NEED_WAKEUP) {
                wake_up(&main_worker_wait[master_id]);
            }
        }
        offloaded = 0;

        sq[wrk_id]->head_table = i;
        sq[wrk_id]->head_entry = j;
        cond_resched();

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

    int ret = 0, head, tail;
    int main_id, master_id;
    unsigned int from_main = 0; // bitmap, if bit set, the task of that main_worker dispatching is completed
    int ctx_id = ((esca_wkr_args_t*)arg)->ctx_id;
    int wrk_id = ((esca_wkr_args_t*)arg)->wrk_id;
    unsigned long timeout = jiffies + ctx[ctx_id]->idle_time;

    DEFINE_WAIT(wq_wait);
    init_waitqueue_head(&wq_worker_wq[wrk_id]);

    esca_table_entry_t* ent;
    struct list_head* self = ((esca_wkr_args_t*)arg)->self;

    master_id = ctx_id;

    // set_cpus_allowed_ptr(current, cpumask_of(WQ_AFF_OFF));

    while (1) {
        // don't protect: only one wq-worker access `df_head`
        head = ctx[ctx_id]->df_head[wrk_id];
        ent = &ctx[ctx_id]->deferred_list[wrk_id][head];

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

        int cursor, new_head, remains = 0;
        spin_lock_irq(&ctx[ctx_id]->df_lock);
        tail = ctx[ctx_id]->df_tail[wrk_id];
        spin_unlock_irq(&ctx[ctx_id]->df_lock);

        cursor = head;

        while (head != tail) {
            ent = &ctx[ctx_id]->deferred_list[wrk_id][head];
            ret = indirect_call(syscall_table_ptr[ent->sysnum], ent->nargs, ent->args);

            if (ret != -EAGAIN) {
                ent->sysret = ret;
                fill_cqe(ctx_id, ent);
                work_node_reg[wrk_id]->cache_comp_num++;
                smp_store_release(&ent->rstatus, BENTRY_EMPTY);
#if 0
                printk(KERN_INFO "In wq-%d, do syscall %d : %d = (%d, %d, %ld, %d) at cpu%d\n", wrk_id,
                    ent->sysnum, ent->sysret, ent->args[0], ent->args[1], ent->args[2], ent->args[3], smp_processor_id());
#endif
            } else {
                remains++;
            }
            head = (head + 1) & ctx[ctx_id]->df_mask;
        }

        new_head = cursor = (head + MAX_DEFERRED_NUM - 1) & DF_MASK;

        while (remains > 0) {
            ent = &ctx[ctx_id]->deferred_list[wrk_id][cursor];

            // condense
            if (ent->rstatus != BENTRY_EMPTY) {
                if (cursor != new_head)
                    move_deferred_entry(ctx_id, wrk_id, cursor, new_head);
                remains--;
                new_head = (new_head + MAX_DEFERRED_NUM - 1) & DF_MASK;
            }

            cursor = (cursor + MAX_DEFERRED_NUM - 1) & DF_MASK;
        }

        // update `df_head`
        head = ctx[ctx_id]->df_head[wrk_id] = (new_head + 1) & DF_MASK;
        ent = &ctx[ctx_id]->deferred_list[wrk_id][head];

        timeout = jiffies + ctx[ctx_id]->idle_time;
        smp_mb();

        if (signal_pending(current))
            goto wq_worker_exit;

        if (work_node_reg[wrk_id]->cache_comp_num != 0) {
            // FIXME: do we need a lock? only 1 wq-worker
            spin_lock_irq(&ctx[ctx_id]->comp_lock);
            ctx[ctx_id]->comp_num += work_node_reg[wrk_id]->cache_comp_num;
            spin_unlock_irq(&ctx[ctx_id]->comp_lock);

            sq[master_id]->wq_has_finished |= ((unsigned int)1 << wrk_id);
            smp_mb();

            if (READ_ONCE(sq[master_id]->flags) & CTX_FLAGS_MAIN_WOULD_SLEEP) {
                // do we need to wake up main-worker?
                if (READ_ONCE(sq[master_id]->flags) & MAIN_WORKER_NEED_WAKEUP) {
                    // printk("need to wake up the main_worker-%d from wq_worker-%d\n", master_id, wrk_id);
                    wake_up(&main_worker_wait[master_id]);
                }
            }

            work_node_reg[wrk_id]->cache_comp_num = 0;
            /*
                Make sure `comp_num` is updated, then allow the incoming tasks to be dispatched to this wq
            */
            smp_mb();
            spin_lock_irq(&ctx[ctx_id]->wq_status_lock);
            WRITE_ONCE(ctx[ctx_id]->wq_status, ctx[ctx_id]->wq_status | ((unsigned int)1 << wrk_id));
            spin_unlock_irq(&ctx[ctx_id]->wq_status_lock);
        }
        continue;

    wq_worker_sleep:
        prepare_to_wait(&wq_worker_wq[wrk_id], &wq_wait, TASK_INTERRUPTIBLE);

        WRITE_ONCE(work_node_reg[wrk_id]->status, work_node_reg[wrk_id]->status & (~WQ_FLAGS_IS_RUNNING));

        spin_lock_irq(&ctx[ctx_id]->wq_status_lock);
        WRITE_ONCE(ctx[ctx_id]->wq_status, ctx[ctx_id]->wq_status | ((unsigned int)1 << wrk_id));
        spin_unlock_irq(&ctx[ctx_id]->wq_status_lock);
        smp_mb();

        schedule();

        // wake up by main_worker
        WRITE_ONCE(work_node_reg[wrk_id]->status, work_node_reg[wrk_id]->status | WQ_FLAGS_IS_RUNNING);
        timeout = jiffies + ctx[ctx_id]->idle_time;
        finish_wait(&wq_worker_wq[wrk_id], &wq_wait);

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
    int n_page, id = p1[2], reg_type = p1[3];
    int ctx_idx, wrk_idx;

    // FIXME: release
    // FIXME: release me if registering CQ
    esca_wkr_args_t* main_wrk_args = (esca_wkr_args_t*)kmalloc(sizeof(esca_wkr_args_t), GFP_KERNEL);
    ctx_idx = main_wrk_args->ctx_id = id / RATIO;
    wrk_idx = main_wrk_args->wrk_id = id;

    esca_table_t** Q;

    if (reg_type == REG_SQ) {
        Q = sq;
    } else if (reg_type == REG_CQ) {
        Q = cq;
        id = id / RATIO;
    } else if (reg_type == REG_LAUNCH) {
        kfree(main_wrk_args);
        goto launching_worker;
    }

    if (p1[0]) {
        /* header is not null */
        get_user_pages((unsigned long)(p1[0]), 1, FOLL_FORCE | FOLL_WRITE, shared_info_pinned_pages, NULL);

        esca_table_t* header = (esca_table_t*)kmap(shared_info_pinned_pages[0]);

        if (reg_type == REG_SQ) {
            for (int i = id; i < id + RATIO; i++) {
                Q[i] = header + i - id;
                init_waitqueue_head(&main_worker_wait[i]);
            }
        } else {
            Q[id] = header;
        }
    } else {
        /* make sure header has been register */
        while (!Q[ctx_idx]) {
            cond_resched();
        }
    }

    /* map tables from user-space to kernel */
    n_page = get_user_pages((unsigned long)(p1[1]), MAX_TABLE_LEN,
        FOLL_FORCE | FOLL_WRITE, table_pinned_pages[id],
        NULL);
    printk("Pin %d pages in worker-%d, for %s registration\n", n_page, id, (reg_type == REG_SQ) ? "SQ" : "CQ");

    for (int j = 0; j < MAX_TABLE_LEN; j++) {
        Q[id]->tables[j] = (esca_table_entry_t*)kmap(table_pinned_pages[id][j]);
        printk("Q[%d][%d]=%p\n", id, j, Q[id]->tables[j]);
    }

    /* initial entry status */
    for (int j = 0; j < MAX_TABLE_LEN; j++)
        for (int k = 0; k < MAX_TABLE_ENTRY; k++)
            Q[id]->tables[j][k].rstatus = BENTRY_EMPTY;

    Q[id]->head_table = Q[id]->tail_table = 0;
    Q[id]->head_entry = Q[id]->tail_entry = 0;
    Q[id]->wq_has_finished = 0;
    Q[id]->main_has_finished = 0;
    Q[id]->idle_time = msecs_to_jiffies(DEFAULT_MAIN_IDLE_TIME);
    WRITE_ONCE(Q[id]->flags, 0 | MAIN_WORKER_NEED_WAKEUP | CTX_FLAGS_MAIN_WOULD_SLEEP);

    if (reg_type == REG_CQ)
        return 0;

    init_waitqueue_head(&wq[ctx_idx]);
    // FIXME: should forward the initialization of `wq_worker_wq`?

    // setup main offloading-thread
    worker_task[id] = create_io_thread_ptr(main_worker, main_wrk_args, -1);
    should_be_submitted[id] = 0;

    // setup context of fastio
    if (wrk_idx % RATIO == 0) {
        ctx[ctx_idx] = kmalloc(sizeof(struct fastio_ctx), GFP_KERNEL);
        ctx[ctx_idx]->df_mask = DF_MASK;
        ctx[ctx_idx]->comp_num = 0;
        ctx[ctx_idx]->nxt_wq = 0;
        ctx[ctx_idx]->idle_time = msecs_to_jiffies(DEFAULT_WQ_IDLE_TIME);

        WRITE_ONCE(ctx[ctx_idx]->wq_status, 0xffffffff);

        for (int i = 0; i < WORKQUEUE_DEFAULT_THREAD_NUMS; i++) {
            ctx[ctx_idx]->df_head[i] = ctx[ctx_idx]->df_tail[i] = 0;
            init_waitqueue_head(&wq_worker_wait[i]);

            for (int j = 0; j < MAX_DEFERRED_NUM; j++) {
                ctx[ctx_idx]->deferred_list[i][j].rstatus = BENTRY_EMPTY;
            }
        }
        spin_lock_init(&ctx[ctx_idx]->cq_lock);
        spin_lock_init(&ctx[ctx_idx]->df_lock);
        spin_lock_init(&ctx[ctx_idx]->comp_lock);
        spin_lock_init(&ctx[ctx_idx]->wq_status_lock);

        create_worker_pool(WORKQUEUE_DEFAULT_THREAD_NUMS, ctx_idx);
    }

    return 0;

launching_worker:
    for (int i = 0; i < WORKQUEUE_DEFAULT_THREAD_NUMS; i++)
        wake_up_new_task_ptr(work_node_reg[i]->task);
    for (int i = (int)p1[0]; i < (int)p1[0] + RATIO; i++)
        wake_up_new_task_ptr(worker_task[i]);
    return 0;
}

static void create_worker_pool(int concurrency, int ctx_id)
{
    struct fastio_work_meta* rhead = kmalloc(sizeof(struct fastio_work_meta), GFP_KERNEL);
    struct fastio_work_meta* fhead = kmalloc(sizeof(struct fastio_work_meta), GFP_KERNEL);

    INIT_LIST_HEAD(&rhead->list);
    INIT_LIST_HEAD(&fhead->list);

    rhead->len = fhead->len = 0;

    for (int arg_idx = 0; arg_idx < concurrency; arg_idx++) {
        struct fastio_work_node* node = kmalloc(sizeof(struct fastio_work_node), GFP_KERNEL);

        work_node_reg[arg_idx] = node;

        wq_wrk_args[arg_idx] = (esca_wkr_args_t*)kmalloc(sizeof(esca_wkr_args_t), GFP_KERNEL);
        wq_wrk_args[arg_idx]->ctx_id = ctx_id;
        wq_wrk_args[arg_idx]->wrk_id = arg_idx;
        wq_wrk_args[arg_idx]->self = &node->list;

        WRITE_ONCE(node->status, 0);
        node->cache_comp_num = 0;
        node->task = create_io_thread_ptr(wq_worker, wq_wrk_args[arg_idx], -1);
        spin_lock_init(&node->wrk_lock);
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

    if (likely(READ_ONCE(sq[i]->flags) & START_WAKEUP_MAIN_WORKER)) {
        wake_up(&main_worker_wait[i]);
    }
}

asmlinkage long sys_esca_wait(const struct __user pt_regs* regs)
{

#if defined(__x86_64__)
    int idx = regs->di;
#elif defined(__aarch64__)
    int idx = regs->regs[0];
#endif

#if defined(__x86_64__)
    mini_ret = regs->si;
#elif defined(__aarch64__)
    mini_ret = regs->regs[1];
#endif

    long res;

    DEFINE_WAIT(_tmp_wait);

    for (;;) {
        prepare_to_wait(&wq[idx], &_tmp_wait, TASK_INTERRUPTIBLE);
        // FIXME: the second condition only correct when using `batch_flush_and_wait_some(1)`
        if ((READ_ONCE(ctx[idx]->status) & CTX_FLAGS_MAIN_DONE))
            break;
        if (!signal_pending(current)) {
            schedule();
            continue;
        }
        goto sys_esca_wait_exit;
    }
    finish_wait(&wq[idx], &_tmp_wait);

    smp_mb();
    WRITE_ONCE(ctx[idx]->status, ctx[idx]->status & (~CTX_FLAGS_MAIN_DONE));

    return get_ready_qlen_and_advance(cq[idx], idx);

sys_esca_wait_exit:
    return 0;
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
    WQ_AFF_OFF = kconfig->wq_affinity_offset;

    printk("Localize: %s\n", ESCA_LOCALIZE ? "Enable" : "Disable");
    printk("MAX_TABLE_ENTRY: %d\n", MAX_TABLE_ENTRY);
    printk("MAX_TABLE_LEN: %d\n", MAX_TABLE_LEN);
    printk("MAX_USR_WORKER: %d\n", MAX_USR_WORKER);
    printk("MAX_KER_WORKER: %d\n", MAX_CPU_NUM);
    printk("AFF_OFF: %d\n", AFF_OFF);
    printk("WQ_AFF_OFF: %d\n", WQ_AFF_OFF);

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
