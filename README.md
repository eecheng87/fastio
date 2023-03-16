# fastio
FastIO is an asynchronous I/O interface that has been developed based on our previous work, [SAIO](https://github.com/eecheng87/SAIO). 
This project is built upon the concept of the io_uring kernel subsystem. 
In FastIO, system calls are handled by kernel workers in a polling manner, which eliminates the need for trapping into the kernel. 
Additionally, FastIO uses wq-worker to offload tasks that handle data not stored in cache, thus reducing the number of CPU mode switches. 
This approach improves the performance of system call-intensive applications, such as key-value servers. 
Through evaluations, we have demonstrated that FastIO can linearly scale the throughput of network servers, such as Redis.

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

configure the value of `max_ker_worker` in `fastio.conf` to spawn varied number of kernel workers.

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