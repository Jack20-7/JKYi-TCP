#ifndef _JKYI_TCP_SOCKET_H_
#define _JKYI_TCP_SOCKET_H_


#include"j_buffer.h"
#include"j_tcp.h"
#include"j_config.h"

#include<pthread.h>
#include<netinet/in.h>

typedef struct _j_socket_map{
    int id;
    int socktype;
    uint32_t opts;

    struct sockaddr_in s_addr;
    union{
        struct _j_tcp_stream* stream;
        struct _j_tcp_listener* listener;
#if J_ENABLE_EPOLL_RB
        void* ep;
#else
        struct _j_epoll* ep;
#endif
    };

    uint32_t epoll;           //注册的事件
    uint32_t events;         //应该也是注册的事件
    uint64_t ep_data;

    TAILQ_ENTRY(_j_socket_map) free_smap_link;
}j_socket_map;

enum j_socket_opts{
    J_TCP_NONBLOCK = 0x01,
    J_TCP_ADDR_BIND = 0x02,
};

j_socket_map* j_allocate_socket(int socktype,int need_lock);
void j_free_socket(int sockid,int need_lock);
j_socket_map* j_get_socket(int sockid);

#if J_ENABLE_SOCKET_C10M
struct _j_socket{
    int id;
    int socktype;

    uint32_t opts;
    struct sockaddr_in s_addr;
    union{
        struct _j_tcp_stream* stream;
        struct _j_tcp_listener* listener;
        void* ep;
    };

    struct _j_socket_table* socktable;
};

struct _j_socket_table{
    size_t max_fds;
    int cur_idx;
    struct _j_socket** sockfds;
    unsigned char* open_fds;
    pthread_spinlock_t lock;
};

struct _j_socket* j_socket_allocate(int socktype);
void j_socket_free(int sockid);
struct _j_socket* j_socket_get(int sockid);
struct _j_socket_table* j_socket_init_fdtable(void);
int j_socket_close_listening(int sockid);
int j_socket_close_stream(int sockid);
#endif

#endif
