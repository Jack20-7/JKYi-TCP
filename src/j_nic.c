#include"j_nic.h"

#include<sys/poll.h>

//初始化
//iframe - netmap绑定的网卡的名称
int j_nic_init(j_thread_context* tctx,const char* ifname){
    if(tctx == NULL){
        return -1;
    }
    j_nic_context* ctx = (j_nic_context*)calloc(1,sizeof(j_nic_context));
    if(ctx == NULL){
        return -2;
    }

    tctx->io_private_context = ctx;

    //struct nmreq是netmap内核和用户空间进行消息传输的结构体
    struct nmreq req;
    memset(&req,0,sizeof(struct nmreq));
    req.nr_arg3 = EXTRA_BUFS;

    ctx->nmr = nm_open(ifname,&req,0,NULL);
    if(ctx->nmr == NULL){
        return -2;
    }

    return 0;
}

int j_nic_read(j_nic_context* ctx,unsigned char** stream){
    if(ctx == NULL){
        return -1;
    }
    struct nm_pkthdr h;
    //从netmap的接收环中读取出一个数据包
    *stream = nm_nextpkt(ctx->nmr,&h);
    return 0;
}

int j_nic_write(j_nic_context* ctx,const void* stream,int length){
    if(ctx == NULL){
        return -1;
    }
    if(stream == NULL){
        return -2;
    }
    if(length == 0){
        return 0;
    }

    nm_inject(ctx->nmr,stream,length);

    return 0;
}


int j_nic_send_pkts(j_nic_context* ctx,int nif){
    if(ctx->snd_pkt_size == 0){
        return 0;
    }
tx_again:
    if(nm_inject(ctx->nmr,ctx->snd_pktbuf,ctx->snd_pkt_size) == 0){
        printf("Failed to send pkt of size %d on interface: %d\n",
                                                   ctx->snd_pkt_size, nif);
        ioctl(ctx->nmr->fd,NIOCTXSYNC,NULL);
        goto tx_again;
    }
    ctx->snd_pkt_size = 0;

    return 0;
}

unsigned char* j_nic_get_wbuffer(j_nic_context* ctx,int nif,uint16_t pktsize){
#if 0
    if(ctx->snd_pkt_size != 0){
        j_nic_send_pkts(ctx,nif);
    }
#endif

    ctx->snd_pkt_size = pktsize;
    return (uint8_t*)ctx->snd_pktbuf;
}

//将netmap接收环的数据读取到nic_context结构体的读缓冲区中去
int j_nic_recv_pkts(j_nic_context* ctx,int ifidx){
    assert(ctx != NULL);

    //当前netmap接收环上面的数据包个数
    int n = ctx->nmr->last_rx_ring - ctx->nmr->first_rx_ring + 1; 
    int i = 0;
    int r = ctx->nmr->cur_rx_ring;
    int got = 0;
    int count = 0;

    for(;i < n && ctx->dev_poll_flag;++i){
        struct netmap_ring* ring;

        r = ctx->nmr->cur_rx_ring + i;
        if(r > ctx->nmr->last_rx_ring){
            r = ctx->nmr->first_rx_ring;
        }

        ring = NETMAP_RXRING(ctx->nmr->nifp,r);  //根据偏移量找到对应的接收环

        for(;!nm_ring_empty(ring) && i != got;++got){
            int idx = ring->slot[ring->cur].buf_idx;
            ctx->rcv_pktbuf[count] = (unsigned char*)NETMAP_BUF(ring,idx);
            ctx->rcv_pkt_len[count] = ring->slot[ring->cur].len;
            ring->head = ring->cur = nm_ring_next(ring,ring->cur);
            count++;
        }
    }

    ctx->nmr->cur_rx_ring = r;
    ctx->dev_poll_flag = 0;

    return count;
}

unsigned char* j_nic_get_rbuffer(j_nic_context* ctx,int nif,uint16_t * len){
    *len = ctx->rcv_pkt_len[nif];
    return ctx->rcv_pktbuf[nif];
}

int j_nic_select(j_nic_context* ctx){
    int rc = 0;
    struct pollfd pfd = {0};
    pfd.fd = ctx->nmr->fd;
    pfd.events = POLLIN;

    if(ctx->idle_poll_count >= IDLE_POLL_COUNT){
        rc = poll(&pfd,1,IDLE_POLL_WAIT);
    }else{
        rc = poll(&pfd,1,0);
    }

    ctx->idle_poll_count = (rc == 0) ? ctx->idle_poll_count + 1 : 0;

    //检测到网卡读到数据
    if(!(pfd.revents && POLLERR)){
        ctx->dev_poll_flag = 1;
    }
    return rc;
}

j_nic_handler j_netmap_handler = {
    .init = j_nic_init,
    .read = j_nic_read,
    .write = j_nic_write,
    .get_wbuffer = j_nic_get_wbuffer,
};
