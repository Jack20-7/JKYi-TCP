#ifndef _JKYI_TCP_TIMER_H_
#define _JKYI_TCP_TIMER_H_

#include"j_tcp.h"
#include"j_queue.h"

#include<stdint.h>

#define RTO_HASH     3000
//.c文件中一共有三个超时队列，对应的是三种类型的定时器
//RTOList       重传队列，上面的连接超时后会进行重传
//TimewaitList  上面的TCP连接是处于Timewait状态的连接
//TimeoutList   保活队列

//对TCP层定时器的设置
typedef struct _j_rto_hashstore{
    uint32_t rto_now_idx;
    uint32_t rto_now_ts;
    TAILQ_HEAD(rto_head,_j_tcp_stream) rto_list[RTO_HASH + 1];
}j_rto_hashstore;

j_rto_hashstore* InitRTOHashstore();

#endif
