#ifndef _JKYI_TCP_ADDR_H_
#define _JKYI_TCP_ADDR_H_

#include"j_queue.h"

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>

//对网络地址进行封装

#define J_MIN_PORT 1024
#define J_MAX_PORT 65535

#ifndef INPORT_ANY
#define INPORT_ANY (uint16_t)0
#endif

//封装的地址结构体类型
typedef struct _j_addr_entry{
    struct sockaddr_in addr;              //只支持IPv4的地址
    TAILQ_ENTRY(_j_addr_entry)addr_link;  //以尾队列的方式串在一起
}j_addr_entry;

typedef struct _j_addr_map{
    j_addr_entry* addrmap[J_MAX_PORT];
}j_addr_map;

//地址池
typedef struct _j_addr_pool{
    j_addr_entry* pool;         //真正的所有的地址结构体
    j_addr_map* mapper;         //为了能够快速查找地址而映入的

    uint32_t addr_base;        //所管理的IP地址的起始地址

    int num_addr;              //IP地址的数量
    int num_entry;
    int num_free;             //当前未使用的地址数
    int num_used;             //当前已经使用了的地址数

    pthread_mutex_t lock;
    TAILQ_HEAD(,_j_addr_entry)free_list;   
    TAILQ_HEAD(,_j_addr_entry)used_list;   
}j_addr_pool;

j_addr_pool* CreateAddressPool(in_addr_t addr_base,int num_addr);
j_addr_pool* CreateAddressPoolPerCore(int core,int num_queues,
                in_addr_t saddr_base,int num_addr,in_addr_t daddr_base,in_port_t dport);
void DestroyAddressPool(j_addr_pool* ap);

int FetchAddress(j_addr_pool* ap,int core,int num_queues,
            const struct sockaddr_in* daddr,struct sockaddr_in* saddr);
int FetchAddressPerCore(j_addr_pool* ap,int core,int num_queues,
            const struct sockaddr_in* daddr,struct sockaddr_in* saddr);

int FreeAddress(j_addr_pool* ap,const struct sockaddr_in* addr);

int GetRSSCPUCore(in_addr_t sip,in_addr_t dip,
             in_port_t sp,in_port_t dp,int num_queues,uint8_t endian_check);
#endif
