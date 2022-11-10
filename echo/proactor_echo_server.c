#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_CONN 1024
#define MAX_MESSAGE_LEN 1024
#define BUF_MASK (MAX_CONN - 1)

#if defined(__aarch64__)
#include "../module/include/aarch64_syscall.h"
#elif defined(__x86_64__)
#include "../module/include/x86_syscall.h"
#endif

char buffer[MAX_CONN][MAX_MESSAGE_LEN];

#include "../module/include/esca.h"

// forward declaration
long batch_start();
long batch_flush();
long batch_flush_and_wait_some(int);
void init_worker(int);
void fastio_user_setup(void);
esca_table_entry_t* get_next_cqe(void);

int get_next_buf(int idx)
{
    return (idx + 1) & BUF_MASK;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Please give a port number: ./proactor_echo_server [port]\n");
        exit(0);
    }

    int portno = strtol(argv[1], NULL, 10);
    struct sockaddr_in serv_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    int buf_mask = MAX_CONN - 1, buf_idx = 0;

    int sock_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    const int val = 1;
    setsockopt(sock_listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // bind and listen
    if (bind(sock_listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Error binding socket...\n");
        exit(1);
    }
    if (listen(sock_listen_fd, 512) < 0) {
        perror("Error listening on socket...\n");
        exit(1);
    }
    printf("proactor echo server listening for connections on port: %d\n", portno);

    // initialize buffer
    for (int i = 0; i < MAX_CONN; i++) {
        memset(buffer[i], 0, sizeof(buffer[i]));
    }

    // initialize fastio user context
    fastio_user_setup();

    // initialize fastio kernel context
    init_worker(0);

    // add first `accept` to monitor for new incoming connections
    accept4(sock_listen_fd, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);

    // start event loop
    while (1) {
        int cq_ret = batch_flush_and_wait_some(1);
#if 0
        if (cq_ret > 0) {
            peek_main_worker();
            // printf("cq_ret = %d\n", cq_ret);
        }
#endif
        // go through all CQEs
        for (int i = 0; i < cq_ret; i++) {
            long res;
            esca_table_entry_t* cqe = get_next_cqe();

            if (!cqe) {
                continue;
            }
            printf("sys[%d](%d,%d,%d)\n", cqe->sysnum, cqe->args[0], cqe->args[1], cqe->args[2]);
            switch (cqe->sysnum) {
            case __ESCA_accept4:
                int cq_fd = cqe->sysret;
                printf("in accept state, res = %d\n", cq_fd);
                if (cq_fd >= 0) {
                    buf_idx = get_next_buf(buf_idx);
                    read(cq_fd, buffer[buf_idx], MAX_MESSAGE_LEN);
                }

                accept4(sock_listen_fd, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);

                break;
            case __ESCA_read:
                res = cqe->sysret;
                printf("in read state, res = %d\n", res);
                if (res < 0) {
                    printf("Read error on file descriptor %ld\n", cqe->args[0]);
                    // FIXME: what is the next state, `close`?
                } else {
                    send(cqe->args[0], cqe->args[1], res, 0);
                }
                break;
            case __ESCA_sendto:
                res = cqe->sysret;
                printf("in write state, res = %d\n", res);
                if (res < 0) {
                    printf("Write error on file descriptor %ld\n", cqe->args[0]);
                    // FIXME: what is the next state, `close`?
                } else {
                    // FIXME: memset?
                    buf_idx = get_next_buf(buf_idx);
                    read(cqe->args[0], buffer[buf_idx], MAX_MESSAGE_LEN);
                }
                break;
            default:
                printf("in default, sysnum = %d\n", cqe->sysnum);
            }
        }
    }
}