#include<pthread.h>

#include"j_tcp.h"
#include"j_socket.h"
#include"j_addr.h"

#define TCP_MAX_SEQ         4294967295

static unsigned int next_seed;

char* state_str[] = {
    "TCP_ST_CLOSED",
    "TCP_ST_LISTEN",
    "TCP_ST_SYN_SENT",
    "TCP_ST_SYN_RCVD",
    "TCP_ST_ESTABLISHED",
    "TCP_ST_FIN_WAIT_1",
    "TCP_ST_FIN_WAIT_2",
    "TCP_ST_CLOSE_WAIT",
    "TCP_ST_CLOSING",
    "TCP_ST_LAST_ACK",
    "TCP_ST_TIME_WAIT",
};

char* close_reason_str[] = {
    "NOT_CLOSED",
    "CLOSE",
    "CLOSED",
    "CONN_FAIL",
    "CONN_LOST",
    "RESET",
    "NO_MEM",
    "DENIED",
    "TIMEDOUT",
};

j_addr_pool* global_addr_pool[ETH_NUM] = {NULL};

extern void RemoveFromRTOList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void RemoveFromTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void RemoveFromTimewaitList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern int GetOutputInterface(uint32_t daddr);

char* TCPStateToString(j_tcp_stream* cur_stream){
    return state_str[cur_stream->state];
}

void InitialTCPStreamManager(){
    next_seed = time(NULL);
}

void RaiseReadEvent(j_tcp_manager* tcp,j_tcp_stream* stream){
    if(stream->socket){
        if(stream->socket->epoll & J_EPOLLIN){
#if J_ENABLE_EPOLL_RB
            epoll_event_callback(tcp->ep,stream->socket->id,J_EPOLLIN);
#else
            j_epoll_add_event(tcp->ep,J_EVENT_QUEUE,stream->socket,J_EPOLLIN);
#endif
#if J_ENABLE_BLOCKING
        }else if(!(stream->socket->opts & J_TCP_NONBLOCK)){
            if(!stream->on_rcv_br_list){
                stream->on_rcv_br_list = 1;
                TAILQ_INSERT_TAIL(&tcp->rcv_br_list,stream,rcv->rcv_br_link);
                tcp->rcv_br_list_cnt++;
            }
#endif
        }
    }else{
        printf("Stream %d:Raising read without a socket!\n",stream->id);
    }
}

void RaiseWriteEvent(j_tcp_manager* tcp,j_tcp_stream* stream){
    if(stream->socket){
        if(stream->socket->epoll & J_EPOLLOUT){
#if J_ENABLE_EPOLL_RB
            epoll_event_callback(tcp->ep,stream->socket->id,J_EPOLLOUT);
#else
            j_epoll_add_event(tcp->ep,J_EVENT_QUEUE,stream->socket,J_EPOLLOUT);
#endif
#if J_ENABLE_BLOCKING
        }else if(!(stream->socket->opts & J_TCP_NONBLOCK)){
            if(!stream->on_snd_br_list){
                stream->on_snd_br_list = 1;
                TAILQ_INSERT_TAIL(&tcp->snd_br_list,stream,snd->snd_br_link);
                tcp->snd_br_list_cnt++;
            }
#endif
        }
    }else{
        printf("Stream %d:Raising write without a socket!",stream->id);
    }
}

void RaiseCloseEvent(j_tcp_manager* tcp,j_tcp_stream* stream){
    if(stream->socket){
        if(stream->socket->epoll & J_EPOLLRDHUP){
#if J_ENABLE_EPOLL_RB
            epoll_event_callback(tcp->ep,stream->socket->id,J_EPOLLRDHUP);
#else
            j_epoll_add_event(tcp->ep,J_EVENT_QUEUE,stream->socket,J_EPOLLRDHUP);
#endif
#if J_ENABLE_BLOCKING
        }else if(!(stream->socket->opts & J_TCP_NONBLOCK)){
            if(!stream->on_rcv_br_list){
                stream->on_rcv_br_list = 1;
                TAILQ_INSERT_TAIL(&tcp->rcv_br_list,stream,rcv->rcv_br_link);
                tcp->rcv_br_list_cnt++;
            }

            if(!stream->on_snd_br_list){
                stream->on_snd_br_list = 1;
                TAILQ_INSERT_TAIL(&tcp->snd_br_list,stream,snd->snd_br_link);
                tcp->snd_br_list_cnt++;
            }
#endif
        }
    }else{
        printf("Stream %d:Raising close without a socket!",stream->id);
    }
}
void RaiseErrorEvent(j_tcp_manager* tcp,j_tcp_stream* stream){
    if(stream->socket){
        if(stream->socket->epoll & J_EPOLLERR){
#if J_ENABLE_EPOLL_RB
            epoll_event_callback(tcp->ep,stream->socket->id,J_EPOLLERR);
#else
            j_epoll_add_event(tcp->ep,J_EVENT_QUEUE,stream->socket,J_EPOLLERR);
#endif
#if J_ENABLE_BLOCKING
        }else if(!(stream->socket->opts & J_TCP_NONBLOCK)){
            if(!stream->on_rcv_br_list){
                stream->on_rcv_br_list = 1;
                TAILQ_INSERT_TAIL(&tcp->rcv_br_list,stream,rcv->rcv_br_link);
                tcp->rcv_br_list_cnt++;
            }
            if(!stream->on_snd_br_list){
                stream->on_snd_br_list = 1;
                TAILQ_INSERT_TAIL(&tcp->snd_br_list,stream,snd->snd_br_link);
                tcp->snd_br_list_cnt++;
            }
#endif
        }
    }else{
        printf("Stream %d:Raising close without a socket!\n",stream->id);
    }
}

j_tcp_stream* CreateTcpStream(j_tcp_manager* tcp,struct _j_socket_map* socket,int type,
                                     uint32_t saddr,uint16_t sport,uint32_t daddr,uint16_t dport){
    j_tcp_stream* stream = NULL;
    pthread_mutex_lock(&tcp->ctx->flow_pool_lock);
    stream = j_mempool_alloc(tcp->flow);
    if(stream == NULL){
        pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
        return NULL;
    }
    memset(stream,0,sizeof(j_tcp_stream));

    stream->rcv = (j_tcp_recv*)j_mempool_alloc(tcp->rcv);
    if(stream->rcv == NULL){
        j_trace_stream("j_mempool_alloc j_tcp_recv error\n");
        j_mempool_free(tcp->flow,stream);
        pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
        return NULL;
    }
    memset(stream->rcv,0,sizeof(j_tcp_recv));

    stream->snd = (j_tcp_send*)j_mempool_alloc(tcp->snd);
    if(stream->snd == NULL){
        j_trace_stream("j_mempool_alloc j_tcp_send error\n");
        j_mempool_free(tcp->rcv,stream->rcv);
        j_mempool_free(tcp->flow,stream);
        pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);

        return NULL;
    }
    memset(stream->snd,0,sizeof(j_tcp_send));

    stream->id = tcp->gid++;
    stream->saddr = saddr;
    stream->sport = sport;
    stream->daddr = daddr;
    stream->dport = dport;

    int ret = StreamHTInsert(tcp->tcp_flow_table,stream);
    if(ret < 0){
        j_mempool_free(tcp->snd,stream->snd);
        j_mempool_free(tcp->rcv,stream->rcv);
        j_mempool_free(tcp->flow,stream);

        pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
        return NULL;
    }

    stream->on_hash_table = 1;
    tcp->flow_cnt++;
    pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);

    if(socket){
        stream->socket = socket;
        socket->stream = stream;
    }

    stream->stream_type = type;
    stream->state = J_TCP_LISTEN;
    stream->on_rto_idx = -1;

    stream->snd->ip_id = 0;
    stream->snd->mss = TCP_DEFAULT_MSS;
    stream->snd->wscale_mine = TCP_DEFAULT_WSCALE;
    stream->snd->wscale_peer = 0;
    stream->snd->nif_out = 0;                 //netmap_if中ring_buffer的标号      

    stream->snd->iss = rand_r(&next_seed) % TCP_MAX_SEQ;
    stream->rcv->irs = 0;

    stream->snd_nxt = stream->snd->iss;
    stream->snd->snd_una = stream->snd->iss;
    stream->snd->snd_wnd = J_SEND_BUFFER_SIZE;

    stream->rcv_nxt = 0;
    stream->rcv->rcv_wnd = TCP_INITIAL_WINDOW;
    stream->rcv->snd_wl1 = stream->rcv->irs - 1;

    stream->snd->rto = TCP_INITIAL_RTO;
    stream->closed = 0;

#if J_ENABLE_BLOCKING
    if(pthread_mutex_init(&stream->rcv->read_lock,NULL)){
        printf("pthread_mutex_init.\n");
        return NULL;
    }

    if(pthread_mutex_init(&stream->snd->write_lock,NULL)){
        pthread_mutex_destroy(&stream->rcv->read_lock);
        printf("pthread_mutex_init\n");
        return NULL;
    }

    if(pthread_cond_init(&stream->rcv->read_cond,NULL)){
        perror("pthread_cond_init of read_cond");
        return NULL;
    }
    if(pthread_cond_init(&stream->snd->write_cond,NULL)){
        perror("pthread_cond_init of write_cond");
        return NULL;
    }
#else
    if(pthread_spin_init(&stream->rcv->read_lock,PTHREAD_PROCESS_PRIVATE)){
        printf("pthread_spin_init.\n");
        return NULL;
    }
    if(pthread_spin_init(&stream->snd->write_lock,PTHREAD_PROCESS_PRIVATE)){
        pthread_spin_destroy(&stream->rcv->read_lock);
        printf("pthread_spin_init.\n");
        return NULL;
    }
#endif

    if(pthread_cond_init(&stream->closed_cond,NULL)){
        perror("pthread_cond_init if closed_cond");
        return NULL;
    }
    if(pthread_mutex_init(&stream->closed_mutex,NULL)){
        perror("pthread_mutex_init of closed_mutex");
        return NULL;
    }

    uint8_t* sa = (uint8_t*)&stream->saddr;
    uint8_t* da = (uint8_t*)&stream->daddr;
    printf("CREATE NEW TCP STREAM%d:"
              "%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (ISS:%u)\n",
              stream->id,
              sa[0],sa[1],sa[2],sa[3],ntohs(stream->sport),
              da[0],da[1],da[2],da[3],ntohs(stream->dport),
              stream->snd->iss);

    return stream;
}
void DestroyTcpStream(j_tcp_manager* tcp,j_tcp_stream* stream){
    uint8_t* sa = (uint8_t*)&stream->saddr;
    uint8_t* da = (uint8_t*)&stream->daddr;

    printf("DESTROY TCP STREAM %d: "
            "%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (%s)\n", stream->id, 
            sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
            da[0], da[1], da[2], da[3], ntohs(stream->dport), 
            close_reason_str[stream->close_reason]);

    if(stream->snd->sndbuf){
        printf("Stream %d:send buffer "
                 "cum_len:%lu,len:%u\n",
                  stream->id,
                  stream->snd->sndbuf->cum_len,
                  stream->snd->sndbuf->len);
    }

    if(stream->rcv->recvbuf){
        printf("Stream %d: recv buffer "
                 "cum_len:%lu,merged_len:%u,last_len:%u\n",
                 stream->id,
                 stream->rcv->recvbuf->cum_len,
                 stream->rcv->recvbuf->merged_len,
                 stream->rcv->recvbuf->last_len);
    }

    int bound_addr = 0;
    struct sockaddr_in addr;
    if(stream->is_bound_addr){
        bound_addr = 1;
        addr.sin_addr.s_addr = stream->saddr;
        addr.sin_port = stream->sport;
    }

    j_tcp_remove_controllist(tcp,stream);
    j_tcp_remove_sendlist(tcp,stream);
    j_tcp_remove_acklist(tcp,stream);

    if(stream->on_rto_idx >= 0){
        RemoveFromRTOList(tcp,stream);
    }
    if(stream->on_timewait_list){
        RemoveFromTimewaitList(tcp,stream);
    }
    RemoveFromTimeoutList(tcp,stream);

#if J_ENALBE_BLOCKING
    pthread_mutex_destroy(&stream->rcv->read_lock);
    pthread_mutex_destroy(&stream->snd->write_lock);
#else
    SBUF_LOCK_DESTROY(&stream->rcv->read_lock);
    SBUF_LOCK_DESTROY(&stream->snd->write_lock);
#endif

    
    assert(stream->on_hash_table == 1);

    if(stream->snd->sndbuf){
        SBFree(tcp->rbm_snd,stream->snd->sndbuf);
        stream->snd->sndbuf = NULL;
    }
    if(stream->rcv->recvbuf){
        RBFree(tcp->rbm_rcv,stream->rcv->recvbuf);
        stream->rcv->recvbuf = NULL;
    }

    pthread_mutex_lock(&tcp->ctx->flow_pool_lock);

    StreamHTRemove(tcp->tcp_flow_table,stream);
    stream->on_hash_table = 0;

    tcp->flow_cnt--;

    if(stream->closed){
        pthread_cond_signal(&stream->closed_cond);
    }
    pthread_mutex_destroy(&stream->closed_mutex);
    pthread_cond_destroy(&stream->closed_cond);

    j_mempool_free(tcp->rcv,stream->rcv);
    j_mempool_free(tcp->snd,stream->snd);
    j_mempool_free(tcp->flow,stream);

    
    pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);

    //对该连接的地址进行缓存
    int ret = -1;
    if(bound_addr){
        if(tcp->ap){
            ret = FreeAddress(tcp->ap,&addr);
        }else{
            int nif = GetOutputInterface(addr.sin_addr.s_addr);
            if(nif < 0){
                printf("nif is negative!\n");
                ret = -1;
            }else{
                int idx = 0;
                ret = FreeAddress(global_addr_pool[idx],&addr);
            }
        }

        if(ret < 0){
            printf("(NEVER HAPPEN)Failed to free address.\n");
        }
    }
}
