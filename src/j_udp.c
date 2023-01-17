#include"j_header.h"
#include"j_nic.h"

void j_udp_pkt(struct udppkt* udp,struct udppkt* udp_rt){
    memcpy(udp_rt,udp,sizeof(struct udppkt));

    memcpy(udp_rt->eh.h_dest,udp->eh.h_source,ETH_ALEN);
    memcpy(udp_rt->eh.h_source,udp->eh.h_dest,ETH_ALEN);

    memcpy(&udp_rt->ip.saddr,&udp->ip.daddr,sizeof(udp->ip.saddr));
    memcpy(&udp_rt->ip.daddr,&udp->ip.saddr,sizeof(udp->ip.saddr));

    memcpy(&udp_rt->udp.source,&udp->udp.dest,sizeof(udp->udp.source));
    memcpy(&udp_rt->udp.dest,&udp->udp.source,sizeof(udp->udp.source));
}

int j_udp_process(j_nic_context* ctx,unsigned char* stream){
    struct udppkt* updh = (struct udppkt*)stream;

    int udp_length = ntohs(updh->udp.len);
    updh->body[udp_length - 8] = '\0';

    struct udppkt udph_rt;
    j_udp_pkt(updh,&udph_rt);
    j_nic_write(ctx,&udph_rt,sizeof(struct udppkt));

    return 0;
}
