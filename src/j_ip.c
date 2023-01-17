#include"j_header.h"
#include"j_tcp.h"
#include"j_nic.h"
#include"j_arp.h"

#include<stdio.h>
#include<stdlib.h>

#define IP_RF 0x8000
#define IP_DF 0x4000       //不分片
#define IP_MF 0x2000       //分片,除了最后一片之外，该标志位的值都为1

int GetOutputInterface(uint32_t daddr){
    return 0;
}

extern j_arp_table* global_arp_table;
extern void j_arp_request(j_tcp_manager* tcp,uint32_t ip,int nif,uint32_t cur_ts);
extern int j_udp_process(j_nic_context* ctx,unsigned char* stream);
extern int j_tcp_process(j_nic_context* ctx,unsigned char* stream);
extern int j_icmp_process(j_nic_context* ctx,unsigned char* stream);

//获取目标mac地址
unsigned char* GetDestinationHWaddr(uint32_t dip){
   unsigned char* d_haddr = NULL;
   int prefix = 0;
   int i = 0;

   //对arp表进行查看
   for(;i < global_arp_table->entries;++i){
       if(global_arp_table->entry[i].prefix == 1){
           if(global_arp_table->entry[i].ip == dip){
               d_haddr = global_arp_table->entry[i].haddr;
               break;
           }
       }else{
          if((dip & global_arp_table->entry[i].ip_mask) == global_arp_table->entry[i].ip_masked){
              if(global_arp_table->entry[i].prefix > prefix){
                  d_haddr = global_arp_table->entry[i].haddr;
                  prefix = global_arp_table->entry[i].prefix;
              }
          }
       }
   }
   return d_haddr;
}


//快速计算出ip首部的检验和
static inline unsigned short ip_fast_csum(const void * iph,unsigned int ihl){
   unsigned int sum;

    __asm__ volatile(   "  movl (%1), %0\n"
        "  subl $4, %2\n"
        "  jbe 2f\n"
        "  addl 4(%1), %0\n"
        "  adcl 8(%1), %0\n"
        "  adcl 12(%1), %0\n"
        "1: adcl 16(%1), %0\n"
        "  lea 4(%1), %1\n"
        "  decl %2\n"
        "  jne  1b\n"
        "  adcl $0, %0\n"
        "  movl %0, %2\n"
        "  shrl $16, %0\n"
        "  addw %w2, %w0\n"
        "  adcl $0, %0\n"
        "  notl %0\n"
        "2:"
    /* Since the input registers which are loaded with iph and ipl
       are modified, we must also specify them as outputs, or gcc
       will assume they contain their original values. */
    : "=r" (sum), "=r" (iph), "=r" (ihl)
    : "1" (iph), "2" (ihl)
    : "memory");
    return (unsigned short)sum;
}


//对IP报文进行发送
uint8_t* IPOutputStandalone(j_tcp_manager* tcp,uint8_t protocol,
                                uint16_t ip_id,uint32_t saddr,uint32_t daddr,uint16_t payloadlen){
    int nif = GetOutputInterface(daddr);
    if(nif < 0){
        return NULL;
    }
    unsigned char* haddr = GetDestinationHWaddr(daddr); 
    if(!haddr){
    }

    struct iphdr* iph = (struct iphdr*)EthernetOutput(tcp,PROTO_IP,0,haddr,payloadlen + IP_HEADER_LEN);
    if(NULL == iph){
        return NULL;
    }

    iph->version = 4;
    iph->ihl = IP_HEADER_LEN >> 2;
    iph->tos = 0;
    iph->tot_len = htons(IP_HEADER_LEN + payloadlen);
    iph->id = htons(ip_id);
    iph->flag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = protocol;
    iph->saddr = saddr;
    iph->daddr = daddr;
    iph->check = ip_fast_csum(iph,iph->ihl);

    return (uint8_t*)(iph + 1);
}

uint8_t* IPOutput(j_tcp_manager* tcp,j_tcp_stream* stream,uint16_t tcplen){
    struct iphdr* iph;
    int nif = 0;

    if(stream->snd->nif_out >= 0){
        nif = stream->snd->nif_out;
    }else{
        nif = GetOutputInterface(stream->daddr);
        stream->snd->nif_out = nif;
    }
    unsigned char* haddr = GetDestinationHWaddr(stream->daddr);
    if(!haddr){
        //j_trace_ip("arp table has not info with daddr\n");
        //如果arp表中找不到的话，那么就需要通过arp请求来解决
        j_arp_request(tcp,stream->daddr,stream->snd->nif_out,tcp->cur_ts);
        return NULL;
    }

    iph = (struct iphdr*)EthernetOutput(tcp,PROTO_IP,stream->snd->nif_out,haddr,tcplen + IP_HEADER_LEN);
    if(!iph){
        return NULL;
    }

    iph->ihl = IP_HEADER_LEN >> 2;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(IP_HEADER_LEN + tcplen);
    iph->id = htons(stream->snd->ip_id++);
    iph->flag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = PROTO_TCP;
    iph->saddr = stream->saddr;
    iph->daddr = stream->daddr;
    //!!!! 这里需要先将ip首部中的check的值清零，然后再通过
    //当前 IP首部 的字段值 计算出对应的检验和.
    //如果不清零的话，就会使得发送方IP层在检验检验和的时候出现问题
    iph->check = 0;
    
    iph->check = ip_fast_csum(iph,iph->ihl);

    return (uint8_t*)(iph + 1);
}

//IP处理函数
int j_ipv4_process(j_nic_context* ctx,unsigned char* stream){
    struct iphdr* iph = (struct iphdr*)(stream + sizeof(struct ethhdr));
    //检查校验和
    if(ip_fast_csum(iph,iph->ihl)){
        j_trace_ip("checksum is error\n");
        return -1;
    }

    if(iph->protocol == PROTO_TCP){
        j_trace_ip("j_tcp_process is called\n");
        j_tcp_process(ctx,stream);
    }else if(iph->protocol == PROTO_UDP){
        j_trace_ip("j_udp_process is called\n");
        j_udp_process(ctx,stream);
    }else if(iph->protocol == PROTO_ICMP){
        j_trace_ip("j_icmp_process is callled\n");
        j_icmp_process(ctx,stream);
    }

    return 0;
}
