#ifndef _JKYI_TCP_EPOLL_H_
#define _JKYI_TCP_EPOLL_H_

#include<stdint.h>
#include"j_config.h"

//自定义数据的类型
typedef enum{
    J_EPOLLNONE     = 0x0000,
    J_EPOLLIN       = 0x0001,
    J_EPOLLPRI      = 0x0002,
    J_EPOLLOUT      = 0x0004,
    J_EPOLLRDNORM   = 0x0040,
    J_EPOLLRDBAND   = 0x0080,
    J_EPOLLWRNORM   = 0x0100,
    J_EPOLLWRBAND   = 0x0200,
    J_EPOLLMSG      = 0x0400,
    J_EPOLLERR      = 0x0008,
    J_EPOLLHUP      = 0x0010,
    J_EPOLLRDHUP    = 0x2000,       //收到对方的fin时会触发的事件，表示读关闭
    J_EPOLLONESHOT  = (1 << 30),
    J_EPOLLET       = (1 << 31),
}j_epoll_type;

//操作的类型
typedef enum{
    J_EPOLL_CTL_ADD = 1,
    J_EPOLL_CTL_DEL = 2,
    J_EPOLL_CTL_MOD = 3,
}j_epoll_op;

typedef struct {
    uint32_t events;   //存储实际发生的事件
    uint64_t data;
}j_epoll_event;

int j_epoll_create(int size);
int j_epoll_ctl(int epid,int op,int sockid,j_epoll_event* event);
int j_epoll_wait(int epid,j_epoll_event* events,int maxevents,int timeout);

#if J_ENABLE_EPOLL_RB

//linux自己的epoll

enum EPOLL_EVENTS {
    EPOLLNONE   = 0x0000,
    EPOLLIN     = 0x0001,
    EPOLLPRI    = 0x0002,
    EPOLLOUT    = 0x0004,
    EPOLLRDNORM = 0x0040,
    EPOLLRDBAND = 0x0080,
    EPOLLWRNORM = 0x0100,
    EPOLLWRBAND = 0x0200,
    EPOLLMSG    = 0x0400,
    EPOLLERR    = 0x0008,
    EPOLLHUP    = 0x0010,       //读写通道关闭会触发该事件.
    EPOLLRDHUP  = 0x2000,       //读通道关闭会触发该事件. 比如当服务器收到客户端发送来的FIN报文之后，就会触发该事件.  EPOLLWRHUP 是写通道关闭的时候，会触发的事件
    EPOLLONESHOT = (1 << 30),
    EPOLLET     = (1 << 31)

};  

#define EPOLL_CTL_ADD   1
#define EPOLL_CTL_DEL   2
#define EPOLL_CTL_MOD   3

typedef union epoll_data{
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
}epoll_data_t;


struct epoll_event{
    uint32_t events;       
    epoll_data_t data;
};

int epoll_create(int size);
int epoll_ctl(int epid,int op,int sockid,struct epoll_event* event);
int epoll_wait(int epid,struct epoll_event* events,int maxevents,int timeout);

int j_epoll_close_socket(int epid);

#endif

#endif
