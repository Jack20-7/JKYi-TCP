#ifndef _JKYI_TCP_HEADER_H_
#define _JKYI_TCP_HEADER_H_

#include"j_config.h"

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<assert.h>
#include<sys/poll.h>


#define ETH_ALEN             6
#define IP_HEADER_LEN        20
#define TCP_HEADER_LEN       20

//下面是协议的协议号

#define PROTO_IP             0x0800
#define PROTO_ARP            0x0806

#define PROTO_UDP            17
#define PROTO_TCP            6
#define PROTO_IGMP           2
#define PROTO_ICMP           1


//下面就是各个层的header

//下面每一个结构体加上一个__attribute__((packed))的目的就是避免编译器对struct进行内存对齐

//14字节
struct ethhdr{
    unsigned char h_dest[ETH_ALEN];       //目标MAC
    unsigned char h_source[ETH_ALEN];     //源MAC
    unsigned short h_proto;               //网络层协议的协议号
}__attribute__((packed));


//20字节
struct iphdr{
    unsigned char ihl:4,                 //IP首部长度
                  version:4    ;         //IP协议版本号
    unsigned char tos;                   //服务类型
    unsigned short tot_len;              //整个IP报文的长度
    unsigned short id;
    unsigned short flag_off;             //标志位 + 偏移量 
    unsigned char ttl;
    unsigned char protocol;              //传输层协议的协议号
    unsigned short check;                //校验和
    unsigned int  saddr;                 //源IP
    unsigned int  daddr;                 //目标IP
}__attribute__((packed));


//8字节
struct udphdr{
    unsigned short source;              //源端口
    unsigned short dest;                //目标端口
    unsigned short len;                 //udp报文长度
    unsigned short check;               //校验和
}__attribute__((packed));

//UDP报文
struct udppkt{
    struct ethhdr eh;
    struct iphdr  ip;
    struct udphdr udp;

    //不能够使用指针，因为如果使用指针的话，那么还需要添加一个成员来存储指针所指向的那一块内存区域中的数据大小
    unsigned char body[128];

}__attribute__((packed));

//TCP首部
struct tcphdr{
    unsigned short source;              //源端口
    unsigned short dest;                //目标端口
    unsigned int seq;                   //序列号
    unsigned int ack_seq;               //确认序列号

    unsigned short res1:4,
                   doff:4,
                   fin:1,
                   syn:1,
                   rst:1,
                   psh:1,
                   ack:1,
                   urg:1,
                   //下面两位没有什么意义
                   ece:1,
                   cwr:1;
    unsigned short window;             //窗口大小
    unsigned short check;              //校验和
    unsigned short urg_ptr;            //紧急指针
}__attribute__((packed));

struct arphdr{
    unsigned short h_type;            //硬件类型,以太网 = 1
    unsigned short h_proto;           //协议类型,要映射的协议地址类型,ip = 0x0800
    unsigned char  h_addrlen;         //硬件地址长度 6
    unsigned char  protolen;          //协议长度     4
    unsigned short oper;              //类型操作.ARP请求 = 1，ARP响应 = 2，RARP请求 = 3，RARP响应 = 4
    unsigned char  smac[ETH_ALEN];    //源MAC
    unsigned int   sip;               //源IP
    unsigned char  dmac[ETH_ALEN];    //目标MAC地址
    unsigned int   dip;               //目标IP
}__attribute__((packed));


struct icmphdr{
    unsigned char type;
    unsigned char code;
    unsigned short check;
    unsigned short identifier; //标识符
    unsigned short seq;        //序号,用来唯一标识ICMP报文
    unsigned char data[32];
}__attribute__((packed));


struct icmppkt{
    struct ethhdr eh;
    struct iphdr  ip;
    struct icmphdr icmp;
}__attribute__((packed));



#endif
