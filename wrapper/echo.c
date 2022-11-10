#define _GNU_SOURCE
#include <sys/socket.h>

int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags)
{
    int idx = this_worker_id * RATIO + (sockfd % RATIO);
    peek_main_worker();
    printf("in accept4\n");
    batch_num++;

    int i = sq[idx]->tail_table;
    int j = sq[idx]->tail_entry;

    sq[idx]->user_tables[i][j].sysnum = __ESCA_accept4;
    sq[idx]->user_tables[i][j].nargs = 4;
    sq[idx]->user_tables[i][j].args[0] = sockfd;
    sq[idx]->user_tables[i][j].args[1] = addr;
    sq[idx]->user_tables[i][j].args[2] = addrlen;
    sq[idx]->user_tables[i][j].args[3] = flags;

    update_tail(sq[idx]);

    esca_smp_store_release(&sq[idx]->user_tables[i][j].rstatus, BENTRY_BUSY);

    /* assume success */
    return 0;
}

ssize_t read(int fd, void* buf, size_t count)
{
    int idx = this_worker_id * RATIO + (fd % RATIO);
    peek_main_worker();
    printf("in read\n");
    batch_num++;

    int i = sq[idx]->tail_table;
    int j = sq[idx]->tail_entry;

    sq[idx]->user_tables[i][j].sysnum = __ESCA_read;
    sq[idx]->user_tables[i][j].nargs = 3;
    sq[idx]->user_tables[i][j].args[0] = fd;
    sq[idx]->user_tables[i][j].args[1] = buf;
    sq[idx]->user_tables[i][j].args[2] = count;

    update_tail(sq[idx]);

    esca_smp_store_release(&sq[idx]->user_tables[i][j].rstatus, BENTRY_BUSY);

    /* assume success */
    return 0;
}

ssize_t send(int sockfd, const void* buf, size_t len, int flags)
{
    int idx = this_worker_id * RATIO + (sockfd % RATIO);
    peek_main_worker();
    printf("in send\n");
    batch_num++;

    int i = sq[idx]->tail_table;
    int j = sq[idx]->tail_entry;

    sq[idx]->user_tables[i][j].sysnum = __ESCA_sendto;
    sq[idx]->user_tables[i][j].nargs = 6;
    sq[idx]->user_tables[i][j].args[0] = sockfd;
    sq[idx]->user_tables[i][j].args[1] = buf;
    sq[idx]->user_tables[i][j].args[2] = len;
    sq[idx]->user_tables[i][j].args[3] = flags;
    sq[idx]->user_tables[i][j].args[4] = NULL;
    sq[idx]->user_tables[i][j].args[5] = 0;

    update_tail(sq[idx]);

    esca_smp_store_release(&sq[idx]->user_tables[i][j].rstatus, BENTRY_BUSY);

    /* assume success */
    return len;
}

int close(int sockfd)
{
    int idx = this_worker_id * RATIO + (sockfd % RATIO);
    peek_main_worker();

    batch_num++;

    int i = sq[idx]->tail_table;
    int j = sq[idx]->tail_entry;

    sq[idx]->user_tables[i][j].sysnum = __ESCA_close;
    sq[idx]->user_tables[i][j].nargs = 1;
    sq[idx]->user_tables[i][j].args[0] = sockfd;

    update_tail(sq[idx]);

    esca_smp_store_release(&sq[idx]->user_tables[i][j].rstatus, BENTRY_BUSY);

    /* assume success */
    return 0;
}
