#ifndef _JKYI_TCP_ARP_H_
#define _JKYI_TCP_ARP_H_

#include"j_header.h"

#define MAX_ARPENTRY 256

typedef struct _j_arp_entry{
    uint32_t ip;
    int8_t prefix;
    uint32_t ip_mask;
    uint32_t ip_masked;
    unsigned char haddr[ETH_ALEN];  //对应的mac地址
}j_arp_entry;

//ARP表
typedef struct _j_arp_table{
    j_arp_entry* entry;
    int entries;
}j_arp_table;

unsigned char* GetDestinationHWaddr(uint32_t ip);
int GetOutputInterface(uint32_t daddr);

int j_arp_register_entry(uint32_t ip,const unsigned char* haddr);
int j_arp_process(j_nic_context* ctx,unsigned char* stream);
int j_arp_init_table(void);

int str2mac(char * mac,char* stream);

#endif
