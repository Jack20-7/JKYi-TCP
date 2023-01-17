#ifndef _JKYI_TCP_NIC_H_
#define _JKYI_TCP_NIC_H_

#include"j_tcp.h"

#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>

#define NETMAP_WITH_LIBS        //使用netmap时必须要加上这个宏

#include"/usr/local/include/net/netmap_user.h"
#pragma pack(1)

#define MAX_PKT_BURST           64    //接收缓冲区最大能够接收的数据包个数
#define MAX_DEVICES             16    //协议栈能够最大能够同时维持的网卡数

#define EXTRA_BUFS              512


#define ETHERNET_FRAME_SIZE     1514  //最大以太网帧的大小
#define ETHERNET_HEADER_LEN     14    //以太网首部的大小

#define IDLE_POLL_COUNT         10
#define IDLE_POLL_WAIT          1

//网卡类，每一个网卡对应一个该结构体对象
typedef struct _j_nic_context{
    struct nm_desc* nmr;    //通过netmap绑定的网卡的描述结构体
    unsigned char snd_pktbuf[ETHERNET_FRAME_SIZE]; //数据帧的发送缓冲区
    unsigned char* rcv_pktbuf[MAX_PKT_BURST];     //从网卡收到的数据会被暂时保存到这里
    uint16_t rcv_pkt_len[MAX_PKT_BURST];           //当前存放的网络包的长度
    uint16_t snd_pkt_size;                         //要发送的网络包的长度
    //和poll技术有关
    uint8_t  dev_poll_flag;                        //网卡上是否有事件产生
    uint8_t  idle_poll_count;                      //无效的poll的次数
}j_nic_context;


//网卡相关操作的结构体
typedef struct _j_nic_handler{
    int (* init)(j_thread_context* ctx,const char* iframe);
    int (* read)(j_nic_context* ctx,unsigned char** stream);
    int (* write)(j_nic_context* ctx,const void* stream,int length);
    unsigned char* (* get_wbuffer)(j_nic_context* ctx,int nif,uint16_t pktsize);
}j_nic_handler;

unsigned char* j_nic_get_wbuffer(j_nic_context* ctx,int nif,uint16_t pktsize);
unsigned char* j_nic_get_rbuffer(j_nic_context* ctx,int nif,uint16_t* len);

//下面两个函数主要用户nic_context结构体缓冲区和netmap内部环形缓冲区的交互
int j_nic_send_pkts(j_nic_context* ctx,int nif);
int j_nic_recv_pkts(j_nic_context* ctx,int ifidx);

//下面两个函数主要是用户缓冲区和netmap内部队列之间的交互
int j_nic_read(j_nic_context* ctx,unsigned char** stream);
int j_nic_write(j_nic_context* ctx,const void* stream,int length);


int j_nic_init(j_thread_context* ctx,const char* ifname);
int j_nic_select(j_nic_context* ctx);                        //对网卡进行轮询，避免频繁的发出中断，影响系统的性能

#if 0
extern j_nic_handler j_netmap_handler;
static j_nic_handler* j_current_handler = &j_netmap_handler;

#define J_NIC_INIT(x,y)   j_current_handler->init(x,y)
#define J_NIC_WRITE(x,y,z) j_current_handler->write(x,y,z)
#define J_NIC_READ(x,y)   j_current_handler->read(x,y)
#define J_NIC_GET_WBUFFER(x,y,z) j_current_handler->get_wbuffer(x,y,z)
#endif

#endif
