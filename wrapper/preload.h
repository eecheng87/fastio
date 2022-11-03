#define _GNU_SOURCE

#define DEPLOY_TAGET 1
#define MAX_TABLE_SIZE 64
#define MAX_POOL_SIZE 900000000

/* optimize: order two */
#define MAX_POOL_IOV_SIZE 1024
#define MAX_POOL_MSG_SIZE 1024
#define IOV_MASK (MAX_POOL_IOV_SIZE - 1)
#define MSG_MASK (MAX_POOL_MSG_SIZE - 1)
#define POOL_UNIT 8

/* syscall number */
#define __NR_esca_register 400
#define __NR_esca_wakeup 401
#define __NR_esca_wait 402
#define __NR_esca_config 403

/* batch table entry info */
#define BENTRY_EMPTY 0
#define BENTRY_BUSY 1

#include "../module/include/esca.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <asm/unistd.h>
#include <errno.h> /* needed by syscall macro */
#ifndef syscall
#include <unistd.h> /* syscall() */
#endif

static inline long
lioo_register(esca_table_t* table,
    esca_table_entry_t* e1,
    esca_table_entry_t* e2)
{
    syscall(__NR_esca_register, table, e1, e2);
}

static inline long
lioo_wait()
{
    syscall(__NR_esca_wait);
}

static inline long
lioo_init_conf(esca_config_t* conf)
{
    syscall(__NR_esca_config, conf);
}

typedef unsigned long long ull;

typedef long (*open_t)(const char* pathname, int flags, mode_t mode);
open_t real_open;
typedef long (*read_t)(int fd, void* buf, size_t count);
read_t real_read;
typedef long (*write_t)(unsigned int fd, const char* buf, size_t count);
write_t real_write;
typedef long (*close_t)(int fd);
close_t real_close;
typedef long (*writev_t)(int fd, const struct iovec* iov, int iovcnt);
writev_t real_writev;
typedef long (*shutdown_t)(int fd, int how);
shutdown_t real_shutdown;
typedef long (*sendfile_t)(int out_fd, int in_fd, off_t* offset, size_t count);
sendfile_t real_sendfile;
typedef long (*sendmsg_t)(int sockfd, const struct msghdr* msg, int flags);
sendmsg_t real_sendmsg;
typedef long (*send_t)(int sockfd, const void* buf, size_t len, int flags);
send_t real_send;