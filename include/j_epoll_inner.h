#ifndef _JKYI_TCP_EPOLL_INNER_H_
#define _JKYI_TCP_EPOLL_INNER_H_

#include"j_socket.h"
#include"j_epoll.h"
#include"j_buffer.h"
#include"j_header.h"

typedef struct _j_epoll_stat{
    uint64_t calls;      //epoll_wait调用的次数
    uint64_t waits;
    uint64_t wakes;      //epoll_wait苏醒的次数

    uint64_t issued;
    uint64_t registered;
    uint64_t invalidated; //处理的过程中发生的异常次数
    uint64_t handled;  //处理的事件个数
}j_epoll_stat;

typedef struct _j_epoll_event_int{
    j_epoll_event ev;
    int sockid;
}j_epoll_event_int;

typedef enum{
    USR_EVENT_QUEUE = 0,
    USR_SHADOW_EVENT_QUEUE = 1,
    J_EVENT_QUEUE = 2,
}j_event_queue_type;

typedef struct _j_event_queue{
    j_epoll_event_int* events;
    int start;
    int end;
    int size;
    int num_events;
}j_event_queue;

typedef struct _j_epoll{
    j_event_queue* usr_queue;
    j_event_queue* usr_shadow_queue;
    j_event_queue* queue;

    uint8_t waiting;
    j_epoll_stat stat;

    pthread_cond_t   epoll_cond;
    pthread_mutex_t epoll_lock;
}j_epoll;

int j_epoll_add_event(j_epoll* ep,int queue_type,struct _j_socket_map* socket,uint32_t event);
int j_close_epoll_socket(int epid);
int j_epoll_flush_events(uint32_t cur_ts);

#if J_ENABLE_EPOLL_RB
struct epitem{
    RB_ENTRY(epitem)   rbn;           //挂在红黑树上的位置
    LIST_ENTRY(epitem) rdlink;        //挂在链表上的位置

    int rdy;
    int sockfd;
    struct epoll_event event;
};

static int sockfd_cmp(struct epitem* ep1,struct epitem* ep2){
    if(ep1->sockfd < ep2->sockfd){
        return -1;
    }else if(ep1->sockfd == ep2->sockfd){
        return 0;
    }

    return 1;
}

RB_HEAD(_epoll_rb_socket,epitem);
RB_GENERATE_STATIC(_epoll_rb_socket,epitem,rbn,sockfd_cmp);

typedef struct _epoll_rb_socket ep_rb_tree;

struct eventpoll{
    ep_rb_tree rbr;        //红黑树
    int rbcnt;

    LIST_HEAD(,epitem) rdlist; //就绪事件队列
    int rdnum;

    int waiting;

    pthread_mutex_t    mtx;   //红黑树的锁
    pthread_spinlock_t lock;  //就绪事件队列的锁

    //下面是调用epoll_wait的时候如果没事件就会阻塞在上面
    pthread_cond_t cond;
    pthread_mutex_t cdmtx;
};

int epoll_event_callback(struct eventpoll* ep,int sockid,uint32_t event);  //协议栈调用的通知事件发生的回调函数
#endif

#endif
