#include"j_header.h"
#include"j_nic.h"
#include"j_arp.h"

#include<pthread.h>

//数据链路层，对应的就是网卡驱动

//该函数应该就是根据收到的数据包计算出它对应的校验和
unsigned short in_cksum(unsigned short* addr,int len){
    register int nleft  = len;
    register unsigned short* w = addr;
    register int sum = 0;
    unsigned short answer = 0;

    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
    if(nleft == 1){
        *(u_char*)(&answer) = *(u_char*)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    
    answer = ~sum;

    return answer;
}

//发送数据
//iplen        要发送的ip数据报的长度
//h_proto      网络层使用的协议
//dst_hadder   目标主机的mac地址
//返回值    要填充的ip数据部分的指针
uint8_t* EthernetOutput(j_tcp_manager* tcp,uint16_t h_proto,
                              int nif,unsigned char* dst_haddr,uint16_t iplen){
   j_thread_context* ctx = tcp->ctx;
   uint8_t* buf = (uint8_t*)j_nic_get_wbuffer(ctx->io_private_context,0,iplen + ETHERNET_HEADER_LEN);
   if(NULL == buf){
       return NULL;
   }

   struct ethhdr* ethh = (struct ethhdr*)buf;
   int i = 0;

   //绑定源max地址
   str2mac((char*)ethh->h_source,J_SELF_MAC);
   for(;i < ETH_ALEN;++i){
       ethh->h_dest[i] = dst_haddr[i];
   }
   ethh->h_proto = htons(h_proto);

   return (uint8_t*)(ethh + 1);
}


//网络层的处理函数
extern int j_ipv4_process(j_nic_context* ctx,unsigned char* stream);

//以太网层的处理函数
static int j_eth_process(j_nic_context* ctx,unsigned char* stream){
    struct ethhdr* eh = (struct ethhdr*)stream;

    if(ntohs(eh->h_proto) == PROTO_IP){
        j_trace_eth("j_ipv4_process is called\n");
        j_ipv4_process(ctx,stream);
    }else if(ntohs(eh->h_proto) == PROTO_ARP){
        j_trace_eth("j_arp_process is called\n");
        j_arp_process(ctx,stream);
    }

    return 0;
}

//要引用的外部的函数
extern j_tcp_manager* j_get_tcp_manager(void);
extern void CheckRtmTimeout(j_tcp_manager* tcp,uint32_t cur_ts,int thresh);
extern void CheckTimewaitExpire(j_tcp_manager* tcp,uint32_t cur_ts,int thresh);
extern void CheckConnectionTimeout(j_tcp_manager* tcp,uint32_t cur_ts,int thresh);


static void* j_tcp_run(void* arg){
    j_nic_context* ctx = (j_nic_context*)arg;

    j_tcp_manager* tcp = j_get_tcp_manager();

    while(1){
        struct pollfd pfd = {0};
        pfd.fd = ctx->nmr->fd;
        pfd.events = POLLIN | POLLOUT;

        int ret = poll(&pfd,1,-1);
        if(ret < 0){
            continue;
        }
        struct timeval cur_ts = {0};
        gettimeofday(&cur_ts,NULL); 
        uint32_t ts = TIMEVAL_TO_TS(&cur_ts);
        if(tcp->flow_cnt > 0){
            //对三个定时队列进行处理
            CheckRtmTimeout(tcp,ts,J_MAX_CONCURRENCY);
            CheckTimewaitExpire(tcp,ts,J_MAX_CONCURRENCY);
            CheckConnectionTimeout(tcp,ts,J_MAX_CONCURRENCY);
            
            //对tcp manager中各个queue中的stream进行处理
            j_tcp_handle_apicall(ts);
        }
        //会对control list中的tcp stream 进行处理
        j_tcp_write_chunks(ts);

        if(!(pfd.revents & POLLERR)){
            ctx->dev_poll_flag = 1;
        }

        if(pfd.revents & POLLIN){
            j_trace_eth("receive packets from internet\n");
            unsigned char* stream = NULL;
            j_nic_read(ctx,&stream);
            j_eth_process(ctx,stream);
        }else if(pfd.revents & POLLOUT){
            j_nic_send_pkts(ctx,0);  //对发送环中的数据进行发送
        }
    }
    return NULL;
}

void j_tcp_setup(void){
    j_thread_context* tctx = (j_thread_context*)calloc(1,sizeof(j_thread_context));
    assert(tctx != NULL);

    printf("j_stack_start\n");

    int ret = j_nic_init(tctx,"netmap:eth0");

    if(ret != 0){
        printf("init nic failed\n");
        return ;
    }

    //对传入的thread_context进行初始化，并且初始化TCP manager
    j_tcp_init_thread_context(tctx);
    j_nic_context* ctx = ctx = (j_nic_context*)tctx->io_private_context;

    j_arp_init_table();                   //arp表的初始化

    pthread_t thread_id;                  //起一个后台线程，来完成协议栈的工作
    ret = pthread_create(&thread_id,NULL,j_tcp_run,ctx);

    assert(ret == 0);
}
