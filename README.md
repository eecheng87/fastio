# fastio
FastIO is a fully asynchronous I/O interface extended from our previous work [SAIO](https://github.com/eecheng87/SAIO).
This project extracts the concept from the recent kernel subsystem io_uring.
System calls will not trap into kernel since there're kernel workers handling them in polling manner.
Also, FastIO exploits wq-worker to offload the tasks which handles the data not in cache.
It enhances the performance of system call intensive application (such as key-value server) by reducing the times of CPU mode switch.
The evaluation shows that FastIO can linearly scale the throughput of network servers such as Redis.

## Build from source
```
git clone https://github.com/eecheng87/fastio.git && cd fastio

# choose target, echos server or redis
make config TARGET=echo
make config TARGET=redis

# build kernel module
sudo make

# load kernel module
make reload

# buildl echo server & launch it
cd echo && make
./proactor_echo_server 12345
```

configure the value of `max_ker_worker` in `esca.conf` to spawn varied number of kernel workers.

## Performance
We compare the throughput (RPS) of conventional [echo-server](https://github.com/eecheng87/fastio/blob/main/echo/epoll_echo_server.c) and the [proactor-like echo-server](https://github.com/eecheng87/fastio/blob/main/echo/proactor_echo_server.c) on the top of FastIO.
We choose [rust_echo_bench](https://github.com/haraldh/rust_echo_bench) as client.
Both server and client are running on eMAG 8180 powered Ampere Arm server with 32 physical cores.

| type/connection numbers | 25     |
| ----------------------- | ------ |
| epoll                   | 82896  |
| fastio (1)              | 82802  |
| fastio (2)              | 161260 |
| fastio (3)              | 257491 |
| fastio (4)              | 301168 |
| fastio (5)              | 393052 |

> fastio (*) refers to server running with * kernel workers.