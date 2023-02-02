#include "j_tcp.h"
#include "j_header.h"
#include "j_nic.h"
#include "j_hash.h"
#include "j_buffer.h"
#include "j_timer.h"

#include <pthread.h>

j_tcp_manager* j_tcp = NULL;

#if 0
static inline int j_tcp_stream_cmp(j_tcp_stream* lhv,j_tcp_stream* rhv){
    if(lhv->saddr < rhv->saddr){
        return -1;
    }else if(lhv->saddr == rhv->saddr){
        if(lhv->sport < rhv->sport){
            return -1;
        }else if(lhv->sport == rhv->sport){
            return 0;
        }else{
            return 1;
        }
    }else{
        return 1;
    }
    assert(0);
}

static inline int j_tcp_timer_cmp(j_tcp_stream* lhv,j_tcp_stream* rhv){
    if(lhv->interval < rhv->interval){
        return -1;
    }else if(lhv->interval == rhv->interval){
        return 0;
    }else{
        return 1;
    }
    assert(0);
}
#endif

static int j_tcp_process_payload(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
            uint32_t cur_ts,uint8_t* payload,uint32_t seq,int payloadlen);

static void j_tcp_process_ack(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t cur_ts,
            struct tcphdr* tcph,uint32_t seq,uint32_t ack_seq,uint16_t window,
            int payloadlen);

static int j_tcp_process_rst(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
                                                              uint32_t ack_seq);

extern unsigned short in_cksum(unsigned short* addr,int len);
extern void UpdateTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void AddtoRTOList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void UpdateRetransmissionTimer(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
                                                                     uint32_t cur_ts);
extern void AddtoTimewaitList(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
                                                                     uint32_t cur_ts);
extern void DestroyTcpStream(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void RemoveFromRTOList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void AddtoTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void RemoveFromTimewaitList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void InitialTCPStreamManager();
extern void RemoveFromTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern void j_tcp_enqueue_acklist(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
              uint32_t cur_ts,uint8_t opt);
extern void j_tcp_addto_acklist(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
extern int j_tcp_parse_timestamp(j_tcp_timestamp* ts,uint8_t* tcpopt,int len);


j_tcp_manager* j_get_tcp_manager(){
    return j_tcp;
}

static inline uint16_t j_calculate_option(uint8_t flag){
    uint16_t optlen = 0;
    if(flag & J_TCPHDR_SYN){
        optlen += J_TCPOPT_MSS_LEN;
        optlen += J_TCPOPT_TIMESTAMP_LEN;
        optlen += 2;
        optlen += J_TCPOPT_WSCALE_LEN + 1;
    }else{
        optlen += J_TCPOPT_TIMESTAMP_LEN;
        optlen += 2;
    }
    //需要是4个字节对齐
    assert(optlen % 4 == 0);
    return optlen;
}
//计算出TCP首部的校验和的值
uint16_t j_tcp_calculate_checksum(uint16_t* buf,uint16_t len,uint32_t saddr,uint32_t daddr){
    uint32_t sum = 0;
    uint16_t* w  = buf;
    int nleft = len;

    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
    if(nleft){
        sum += *w & ntohs(0xFF00);
    }

    sum += (saddr & 0x0000FFFF) + (saddr >> 16);
    sum += (daddr & 0x0000FFFF) + (daddr >> 16);
    sum += htons(len);
    sum += htons(PROTO_TCP);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    sum = ~sum;

    return(uint16_t)sum;
}

//选项的格式为
//type   8bits
//length 8bits
//data   nbits
static void j_tcp_generate_timestamp(j_tcp_stream* cur_stream,uint8_t* tcpopt,
                                                                     uint32_t cur_ts){
    uint32_t* ts = (uint32_t*)(tcpopt + 2);
    tcpopt[0] = TCP_OPT_TIMESTAMP;
    tcpopt[1] = J_TCPOPT_TIMESTAMP_LEN;

    ts[0] = htonl(cur_ts);
    ts[1] = htonl(cur_stream->rcv->ts_recent);
}

static void j_tcp_generate_options(j_tcp_stream* cur_stream,uint32_t cur_ts,
                                uint8_t flags,uint8_t * tcpopt,uint16_t optlen){
    int i = 0;
    if(flags & J_TCPHDR_SYN){
        //下面是SYN报文能够携带的选项
        uint16_t mss = cur_stream->snd->mss;

        tcpopt[i++] = TCP_OPT_MSS;
        tcpopt[i++] = J_TCPOPT_MSS_LEN;
        tcpopt[i++] = mss >> 8;        // /256
        tcpopt[i++] = mss % 256;       // %256

        //加上两个字节的填充
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_NOP;

        j_tcp_generate_timestamp(cur_stream,tcpopt + i,cur_ts);
        i += J_TCPOPT_TIMESTAMP_LEN;

        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_WSCALE;
        tcpopt[i++] = J_TCPOPT_WSCALE_LEN;
        tcpopt[i++] = cur_stream->snd->wscale_mine;
    }else{
        //如果表示SYN报文的话，那么options字段就只能够携带上timestamp这个选项
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_NOP;
        j_tcp_generate_timestamp(cur_stream,tcpopt + i,cur_ts);
        i += J_TCPOPT_TIMESTAMP_LEN;
    }

    assert(i == optlen);
}

uint16_t j_calculate_chksum(uint16_t* buf,uint16_t len,uint32_t saddr,uint32_t daddr){
    uint32_t  sum = 0;
    uint16_t* w = buf;
    int nleft = len;

    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
    if(nleft){
        sum += *w & ntohs(0xFF00);
    }

    sum += (saddr & 0x0000FFFF) + (saddr >> 16);
    sum += (daddr * 0x0000FFFF) + (daddr >> 16);
    sum += htons(len);
    sum += htons(PROTO_TCP);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    sum = ~sum;

    return (uint16_t)sum;
}

j_sender* j_tcp_getsender(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
#if J_ENABLE_MULTI_NIC
    if(cur_stream->snd->nif_out < 0){
        return tcp->g_sender;
    }else{
        return tcp->n_sender[0];
    }
#else
    return tcp->g_sender;
#endif
}

void j_tcp_addto_acklist(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    j_sender* sender = j_tcp_getsender(tcp,cur_stream);
    assert(sender != NULL);

    if(!cur_stream->snd->on_ack_list){
        cur_stream->snd->on_ack_list = 1;
        TAILQ_INSERT_TAIL(&sender->ack_list,cur_stream,snd->ack_link);
        sender->ack_list_cnt++;
    }
}

void j_tcp_addto_controllist(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    j_sender* sender = j_tcp_getsender(tcp,cur_stream);
    assert(sender != NULL);

    if(!cur_stream->snd->on_control_list){
        cur_stream->snd->on_control_list = 1;
        TAILQ_INSERT_TAIL(&sender->control_list,cur_stream,snd->control_link);
        sender->control_list_cnt++;
    }
}

void j_tcp_addto_sendlist(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    j_sender* sender = j_tcp_getsender(tcp,cur_stream);
    assert(sender != NULL);

    if(!cur_stream->snd->sndbuf){
        assert(0);
        return ;
    }

    j_trace_tcp("j_tcp_addto_sendlist--> %d\n",cur_stream->snd->on_send_list);
    if(!cur_stream->snd->on_send_list){
        cur_stream->snd->on_send_list = 1;
        TAILQ_INSERT_TAIL(&sender->send_list,cur_stream,snd->send_link);
        sender->send_list_cnt++;
    }
}

void j_tcp_remove_acklist(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    j_sender* sender = j_tcp_getsender(tcp,cur_stream);
    assert(sender != NULL);

    if(cur_stream->snd->on_ack_list){
        cur_stream->snd->on_ack_list = 0;
        TAILQ_REMOVE(&sender->ack_list,cur_stream,snd->ack_link);
        sender->ack_list_cnt--;
    }
}

void j_tcp_remove_controllist(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    j_sender* sender = j_tcp_getsender(tcp,cur_stream);
    assert(sender != NULL);

    if(cur_stream->snd->on_control_list){
        cur_stream->snd->on_control_list = 0;
        TAILQ_REMOVE(&sender->control_list,cur_stream,snd->control_link);
        sender->control_list_cnt--;
    }
}

void j_tcp_remove_sendlist(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    j_sender* sender = j_tcp_getsender(tcp,cur_stream);
    assert(sender != NULL);

    if(cur_stream->snd->on_send_list){
        cur_stream->snd->on_send_list = 0;
        TAILQ_REMOVE(&sender->send_list,cur_stream,snd->send_link);
        sender->send_list_cnt--;
    }
}

void j_tcp_parse_options(j_tcp_stream* cur_stream,uint32_t cur_ts,uint8_t* tcpopt,int len){
    int i = 0;
    unsigned int opt,optlen;

    for(;i < len;){
        opt = *(tcpopt + i++);
        if(opt == TCP_OPT_END){
            break;
        }else if(opt == TCP_OPT_NOP){
            continue;
        }else{
            optlen = *(tcpopt + i++);
            if(i + optlen - 2 > (unsigned int)len){
                break;
            }
            if(opt == TCP_OPT_MSS){
                cur_stream->snd->mss = *(tcpopt + i++) << 8;
                cur_stream->snd->mss += *(tcpopt + i++);
                cur_stream->snd->eff_mss = cur_stream->snd->mss;
                cur_stream->snd->eff_mss -= (J_TCPOPT_TIMESTAMP_LEN + 2);
            }else if(opt == TCP_OPT_WSCALE){
                cur_stream->snd->wscale_peer = *(tcpopt + i++);
            }else if(opt == TCP_OPT_SACK_PERMIT){
                cur_stream->sack_permit = 1;
                j_trace_tcp("Remote SACK permited.\n");
            }else if(opt == TCP_OPT_TIMESTAMP){
                cur_stream->saw_timestamp = 1;
                cur_stream->rcv->ts_recent = ntohl(*(uint32_t*)(tcpopt + i++));
                cur_stream->rcv->ts_last_ts_upd = cur_ts;
                i += 8;
            }else{
                i += optlen - 2;
            }
        }
    }
}

void j_tcp_enqueue_acklist(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t cur_ts,
                                 uint8_t opt){
   if(!(cur_stream->state == J_TCP_ESTABLISHED 
            || cur_stream->state == J_TCP_CLOSE_WAIT
            || cur_stream->state == J_TCP_FIN_WAIT_1
            || cur_stream->state == J_TCP_FIN_WAIT_2)){
       //如果当前TCP连接的状态不是 established 、close_wait、fin_wait1、fin_wait2
       j_trace_tcp("Stream %d:Enqueueing ack at state %d\n",
                      cur_stream->id,cur_stream->state);
   }

   if(opt == ACK_OPT_NOW){
       if(cur_stream->snd->ack_cnt < cur_stream->snd->ack_cnt + 1){
           //这个判断条件有点搞不懂，感觉多此一举
           cur_stream->snd->ack_cnt++;
       }
   }else if(opt == ACK_OPT_AGGREGATE){
       if(cur_stream->snd->ack_cnt == 0){
           cur_stream->snd->ack_cnt = 1;
       }
   }else if(opt == ACK_OPT_WACK){
       cur_stream->snd->is_wack = 1;
   }

   j_tcp_addto_acklist(tcp,cur_stream);
}

int j_tcp_parse_timestamp(j_tcp_timestamp* ts,uint8_t* tcpopt,int len){
    int i = 0;
    unsigned int opt,optlen;

    for(;i < len;++i){
        opt = *(tcpopt + i++);
        if(opt == TCP_OPT_END){
            break;
        }else if(opt == TCP_OPT_NOP){
            continue;
        }else{
            optlen = *(tcpopt + i++);
            if(i + optlen - 2 > (unsigned int) len){
                break;
            }

            if(opt == TCP_OPT_TIMESTAMP){
                ts->ts_val = ntohl(*(uint32_t*)(tcpopt + i));
                ts->ts_ref = ntohl(*(uint32_t*)(tcpopt + i + 4));
                return 1;
            }else{
                i += optlen - 2;
            }
        }
    }
    return 0;
}

//发送TCP报文
int j_tcppkt_alone(j_tcp_manager* tcp,
                         uint32_t saddr,uint16_t sport,uint32_t daddr,uint16_t dport,
                         uint32_t seq,uint32_t ack_seq,uint16_t window,uint8_t flags,
                         uint8_t* payload,uint16_t payloadlen,
                         uint32_t cur_ts,uint32_t echo_ts){
    int optlen = j_calculate_option(flags);
    if(payloadlen > TCP_DEFAULT_MSS + optlen){
        j_trace_tcp("Payload size exceed MSS.\n");
        assert(0);
        return -1;
    }

    struct tcphdr* tcph = (struct tcphdr*)IPOutputStandalone(tcp,PROTO_TCP,
                                     0,saddr,daddr,TCP_HEADER_LEN + optlen + payloadlen);
    if(tcph == NULL){
        return -1;
    }

    memset(tcph,0,TCP_HEADER_LEN + optlen);
    tcph->source = sport;
    tcph->dest = dport;

    if(flags & J_TCPHDR_SYN){
        tcph->syn = 1;
    }
    if(flags & J_TCPHDR_FIN){
        tcph->fin = 1;
    }
    if(flags & J_TCPHDR_RST){
        tcph->rst = 1;
    }
    if(flags & J_TCPHDR_PSH){
        tcph->psh = 1;
    }

    tcph->seq = htonl(seq);
    if(flags & J_TCPHDR_ACK){
        tcph->ack = 1;
        tcph->ack_seq = htonl(ack_seq);
    }
    tcph->window = htons(MIN(window,TCP_MAX_WINDOW));
    uint8_t* tcpopt = (uint8_t*)tcph + TCP_HEADER_LEN;
    uint32_t* ts = (uint32_t*)(tcpopt + 4);

    tcpopt[0] = TCP_OPT_NOP;
    tcpopt[1] = TCP_OPT_NOP;
    tcpopt[2] = TCP_OPT_TIMESTAMP;
    tcpopt[3] = J_TCPOPT_TIMESTAMP_LEN;

    ts[0] = htonl(cur_ts);
    ts[1] = htonl(echo_ts);

    //单位是4个字节，所以需要/4
    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;

    //将要发送的数据拷贝过来
    if(payloadlen > 0){
        memcpy((uint8_t*)tcph + TCP_HEADER_LEN + optlen,payload,payloadlen);
    }
    tcph->check = j_calculate_chksum((uint16_t*)tcph,
                            TCP_HEADER_LEN + optlen + payloadlen,saddr,daddr);

    if(tcph->syn || tcph->fin){
        payloadlen++;
    }

    return payloadlen;
}

//发送TCP报文.
int j_tcp_send_tcppkt(j_tcp_stream* cur_stream,uint32_t cur_ts,uint8_t flags,
                                              uint8_t* payload,uint16_t payloadlen){
    uint16_t optlen = j_calculate_option(flags);
    j_trace_tcp("payload:%d, mss:%d, optlen:%d, data:%s\n",
                      payloadlen,cur_stream->snd->mss,optlen,payload); 
    if(payloadlen > cur_stream->snd->mss + optlen){
        j_trace_tcp("Payload size exceeds MSS.\n");
        return -1;
    }

    j_tcp_manager* tcp = j_get_tcp_manager();
    if(tcp == NULL){
        return -2;
    }

    struct tcphdr* tcph = (struct tcphdr*)IPOutput(tcp,cur_stream,
                                                TCP_HEADER_LEN + optlen + payloadlen);
    if(tcph == NULL){
        //j_trace_tcp("IPOutput error\n");
        return -2;
    }

    memset(tcph,0,TCP_HEADER_LEN + optlen);
    tcph->source = cur_stream->sport;
    tcph->dest = cur_stream->dport;

    if(flags & J_TCPHDR_SYN){
        tcph->syn = 1;
        if(cur_stream->snd_nxt != cur_stream->snd->iss){
            j_trace_tcp("Stream %d:wired SYN sequence."
                          "snd_nxt:%u, iss:%u\n",cur_stream->id,
                           cur_stream->snd_nxt,cur_stream->snd->iss);
        }
    }

    if(flags & J_TCPHDR_RST){
        j_trace_tcp("Stream %d: Sending RST.\n",cur_stream->id);
        tcph->rst= 1;
    }

    if(flags & J_TCPHDR_PSH){
        tcph->psh = 1;
    }
    //设置报文的序列号
    if(flags & J_TCPHDR_CWR){
        //需要先发发送一个探测报文探测出新的窗口大小
        tcph->seq = htonl(cur_stream->snd_nxt - 1);
        j_trace_tcp("Stream %u Sending ACK to get new window advertisement."
                       "seq:%u,peer_wnd : %u,snd_nxt - snd_ack:%u\n",
                       cur_stream->id,
                       cur_stream->snd_nxt - 1,cur_stream->snd->peer_wnd,
                       cur_stream->snd_nxt - cur_stream->snd->snd_una);
    }else if(flags & J_TCPHDR_FIN){
        tcph->fin = 1;
        if(cur_stream->snd->fss == 0){
            j_trace_tcp("Stream %u: not fss set.closed:%u\n",
                          cur_stream->id,cur_stream->closed);
        }
        tcph->seq = htonl(cur_stream->snd->fss);
        cur_stream->snd->is_fin_sent = 1;
        j_trace_tcp("Stream %u:Send FIN,seq:%u,ack_seq: %u\n",
                      cur_stream->id,cur_stream->snd_nxt,cur_stream->rcv_nxt);
    }else{
        tcph->seq = htonl(cur_stream->snd_nxt);
    }

    if(flags & J_TCPHDR_ACK){
        //j_trace_tcp("send ACK Packet\n");
        tcph->ack = 1;
        tcph->ack_seq = htonl(cur_stream->rcv_nxt);

        cur_stream->snd->ts_lastack_sent = cur_ts;
        cur_stream->last_active_ts = cur_ts;

        //更新该连接在TimeoutList中的位置
        UpdateTimeoutList(tcp,cur_stream);
    }

    uint8_t wscale = 0;
    if(flags & J_TCPHDR_SYN){
        wscale = 0;
    }else{
        wscale = cur_stream->snd->wscale_mine;
    }

    uint32_t window32 = cur_stream->rcv->rcv_wnd >> wscale;
    tcph->window = htons((uint16_t)MIN(window32,TCP_MAX_WINDOW));

    if(window32 == 0){
        cur_stream->need_wnd_adv = 1;
    }

    j_tcp_generate_options(cur_stream,cur_ts,flags,(uint8_t*)tcph + TCP_HEADER_LEN,optlen);
    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    if(payloadlen > 0){
        memcpy((uint8_t*)tcph + TCP_HEADER_LEN + optlen,payload,payloadlen);
    }

    tcph->check = j_tcp_calculate_checksum((uint16_t*)tcph,
                                           TCP_HEADER_LEN + optlen + payloadlen,
                                           cur_stream->saddr,cur_stream->daddr);

    cur_stream->snd_nxt += payloadlen;

    if(tcph->syn || tcph->fin){
        //由于SYN/FIN报文不能够携带数据，所以它们的payloadlen = 0.
        //但是它们仍然需要占据1个字节长度的序列号，所以需要++一下
        cur_stream->snd_nxt++;
        payloadlen++;
    }

    if(payloadlen > 0){
        if(cur_stream->state > J_TCP_ESTABLISHED){
            j_trace_tcp("Payload after ESTABLISHD: length %d,snd_nxt:%u\n",
                          payloadlen,cur_stream->snd_nxt);
        }

        cur_stream->snd->ts_rto = cur_ts + cur_stream->snd->rto;
        j_trace_tcp("Updating retransmission timer."
                     "cur_ts:%u,rto:%u,ts_rto:%u,mss:%d\n",
                     cur_ts,cur_stream->snd->rto,cur_stream->snd->ts_rto,
                     cur_stream->snd->mss);
        AddtoRTOList(tcp,cur_stream);
        j_trace_tcp("j_tcp_send_tcppkt: %d\n",payloadlen);
    }
    return payloadlen;
}

//判断是否存在地址为 ip + port 的listener
static inline int j_tcp_filter_synpkt(j_tcp_manager* tcp,uint32_t ip,uint16_t port){
    struct sockaddr_in* addr;
    j_trace_tcp("FilterSYNPacket 111:0x%x,port:%d\n",ip,port);
    struct _j_tcp_listener* listener = 
              (struct _j_tcp_listener*)ListenerHTSearch(tcp->listeners,&port);
    if(listener == NULL){
        return 0;
    }

    j_trace_tcp("FilterSYNPacket 222:0x%x,port:%d\n",ip,port);
    addr = &listener->socket->s_addr;
    if(addr->sin_port == port){
        if(addr->sin_addr.s_addr != INADDR_ANY){
            if(ip == addr->sin_addr.s_addr){
                return 1;
            }
            return 0;
        }
        if(ip == J_SELF_IP_HEX){
            return 1;
        }
    }
    return 0;
}

//被动建立连接，也就是收到了对端发送来的SYN报文
static inline j_tcp_stream* j_tcp_passive_open(j_tcp_manager* tcp,uint32_t cur_ts,
              const struct iphdr* iph,const struct tcphdr* tcph,uint32_t seq,
                                                                      uint16_t window){
    j_tcp_stream* cur_stream = CreateTcpStream(tcp,NULL,J_TCP_SOCK_STREAM,
                                 iph->daddr,tcph->dest,iph->saddr,tcph->source);
    if(cur_stream == NULL){
        j_trace_tcp("INFO:Could not allocate tcp_stream!\n");
        return NULL;
    }

    cur_stream->rcv->irs = seq;
    cur_stream->snd->peer_wnd = window;
    cur_stream->rcv_nxt = cur_stream->rcv->irs;  // 这里暂时先设置为 = seq，后面在调用j_handle_listen的时候，当判断是syn报文的时候，会+1
    cur_stream->snd->cwnd = 1;  //慢启动

#if 1
    cur_stream->rcv->recvbuf = RBInit(tcp->rbm_rcv,cur_stream->rcv->irs + 1);
    if(!cur_stream->rcv->recvbuf){
        cur_stream->state = J_TCP_CLOSED;
        cur_stream->close_reason = TCP_NO_MEM;
    }
#endif

    j_tcp_parse_options(cur_stream,cur_ts,(uint8_t*)tcph + TCP_HEADER_LEN,
                           (tcph->doff << 2) - TCP_HEADER_LEN);
    j_trace_tcp("j_tcp_passive_open:%d,%d\n",
                    cur_stream->rcv_nxt,cur_stream->snd->mss);

    return cur_stream;
}

//主动建立连接一方,应该时收到了返回的SYN + ACK报文
int j_tcp_active_open(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t cur_ts,
                    struct tcphdr* tcph,uint32_t seq,uint32_t ack_seq,uint16_t window){
    cur_stream->rcv->irs = seq;
    cur_stream->snd_nxt = ack_seq;
    cur_stream->snd->peer_wnd = window;
    cur_stream->rcv->snd_wl1 = cur_stream->rcv->irs - 1;
    cur_stream->rcv_nxt = cur_stream->rcv->irs + 1;
    cur_stream->rcv->last_ack_seq = ack_seq;

    j_tcp_parse_options(cur_stream,cur_ts,(uint8_t*)tcph + TCP_HEADER_LEN,
                                             (tcph->doff << 2) - TCP_HEADER_LEN);
    cur_stream->snd->cwnd = ((cur_stream->snd->cwnd == 1) ? 
                             (cur_stream->snd->cwnd * 2) : cur_stream->snd->mss);
    cur_stream->snd->ssthresh = cur_stream->snd->mss * 10;

    UpdateRetransmissionTimer(tcp,cur_stream,cur_ts);

    return 1;
}

static inline int j_tcp_validseq(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
                                 uint32_t cur_ts,struct tcphdr* tcph,uint32_t seq,
                                 uint32_t ack_seq,int payloadlen){
    if(!tcph->rst && cur_stream->saw_timestamp){
        //如果开启了时间戳功能
        j_tcp_timestamp ts;
        if(!j_tcp_parse_timestamp(&ts,(uint8_t*)tcph + TCP_HEADER_LEN,
                                   (tcph->doff << 2) - TCP_HEADER_LEN)){
            j_trace_tcp("No timestamp found.\n");
            return 0;
        }

        if(TCP_SEQ_LT(ts.ts_val,cur_stream->rcv->ts_recent)){
            //该报文是一个过期的报文
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_NOW);
        }else{
            if(TCP_SEQ_GT(ts.ts_val,cur_stream->rcv->ts_recent)){
                //收到的报文时间戳没有问题
                j_trace_tcp("Timetamp update.cur:%u,prior:%u "
                              "(time diff :%uus\n)\n",
                              ts.ts_val,cur_stream->rcv->ts_recent,
                              TS_TO_USEC(cur_ts - cur_stream->rcv->ts_last_ts_upd));
                cur_stream->rcv->ts_last_ts_upd = cur_ts;
            }
            cur_stream->rcv->ts_recent = ts.ts_val;
            cur_stream->rcv->ts_lastack_rcvd = ts.ts_ref;
        }
    }

    if(!TCP_SEQ_BETWEEN(seq + payloadlen,cur_stream->rcv_nxt,
                         cur_stream->rcv_nxt + cur_stream->rcv->rcv_wnd)){
        if(tcph->rst){
            return 0;
        }

        if(cur_stream->state == J_TCP_ESTABLISHED){
            if(seq + 1 == cur_stream->rcv_nxt){
                j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_AGGREGATE);
                return 0;
            }

            if(TCP_SEQ_LEQ(seq,cur_stream->rcv_nxt)){
                //j_trace_tcp("seq <= cur_stream->rcv_nxt\n");
                j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_AGGREGATE);
            }else{
                j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_NOW);
            }
        }else{
            if(cur_stream->state == J_TCP_TIMEWAIT){
                j_trace_tcp("Stream %d:tw expire update to %u\n",
                               cur_stream->id,cur_stream->rcv->ts_tw_expire);
                AddtoTimewaitList(tcp,cur_stream,cur_ts);
            }
            j_tcp_addto_controllist(tcp,cur_stream);
        }
        return 0;
    }
    return 1;
}
static j_tcp_stream* j_create_stream(j_tcp_manager* tcp,uint32_t cur_ts,
                                      const struct iphdr* iph,int op_len,
                                      const struct tcphdr* tcph,uint32_t seq,
                                      uint32_t ack_seq,int payloadlen,uint16_t window){
    j_tcp_stream* cur_stream;
    int ret = 0;
    if(tcph->syn && !tcph->ack){
        //收到的是syn报文的话
        j_trace_tcp("ip:0x%x,port:%d\n",iph->daddr,ntohs(tcph->dest));
        ret = j_tcp_filter_synpkt(tcp,iph->daddr,tcph->dest);
        if(!ret){
            j_trace_tcp("Refusing SYN Packet.\n");
            j_tcppkt_alone(tcp,iph->daddr,tcph->dest,iph->saddr,tcph->source,
                              0,seq + payloadlen + 1,0,J_TCPHDR_RST | J_TCPHDR_ACK,
                              NULL,0,cur_ts,0);
            return NULL;
        }
        j_trace_tcp("j_create_stream\n");
        cur_stream = j_tcp_passive_open(tcp,cur_ts,iph,tcph,seq,window);
        if(!cur_stream){
            j_trace_tcp("Not available space in flow pool.\n");
            j_tcppkt_alone(tcp,iph->daddr,tcph->dest,iph->saddr,tcph->source,
                           0,seq + payloadlen + 1,0,J_TCPHDR_RST | J_TCPHDR_ACK,
                                                                   NULL,0,cur_ts,0);
            return NULL;
        }
        return cur_stream;
    }else if(tcph->rst){
        j_trace_tcp("Reset packet comes\n");
    }else{
        if(tcph->ack){
            j_tcppkt_alone(tcp,iph->daddr,tcph->dest,iph->saddr,tcph->source,
                                            ack_seq,0,0,J_TCPHDR_RST,NULL,0,cur_ts,0);
        }else{
            j_tcppkt_alone(tcp,iph->daddr,tcph->dest,iph->saddr,tcph->source,
                            0,seq + payloadlen,0,J_TCPHDR_RST | J_TCPHDR_ACK,
                            NULL,0,cur_ts,0);
        }
        return NULL;
    }
    return NULL;
}

static void j_tcp_flush_accept_event(j_tcp_listener* listener){
    pthread_mutex_lock(&listener->accept_lock);
    if(!StreamQueueIsEmpty(listener->acceptq)){
        pthread_cond_signal(&listener->accept_cond);
    }
    pthread_mutex_unlock(&listener->accept_lock);
}

static void j_tcp_flush_read_event(j_tcp_recv* rcv){
    pthread_mutex_lock(&rcv->read_lock);
    if(rcv->recvbuf->merged_len >= 0){
        pthread_cond_signal(&rcv->read_cond);
    }
    pthread_mutex_unlock(&rcv->read_lock);
}
static void j_tcp_flush_send_event(j_tcp_send* snd){
    pthread_mutex_lock(&snd->write_lock);
    if(snd->snd_wnd > 0){
        pthread_cond_signal(&snd->write_cond);
    }
    pthread_mutex_unlock(&snd->write_lock);
}

static void j_tcp_handle_listen(j_tcp_manager* tcp,uint32_t cur_ts,
                                 j_tcp_stream* cur_stream,struct tcphdr* tcph){
    if(tcph->syn){
        if(cur_stream->state == J_TCP_LISTEN){
            cur_stream->rcv_nxt++;
        }
        cur_stream->state = J_TCP_SYN_RCVD;
        j_trace_tcp("Stream %d: TCP_ST_SYN_RECV.\n",cur_stream->id);
        j_tcp_addto_controllist(tcp,cur_stream);
    }else{
        j_trace_tcp("Stream %d (TCP_ST_LISTEN):"
                      "Packet without SYN.\n",cur_stream->id);
        assert(0);
    }
}

static void j_tcp_handle_syn_sent(j_tcp_manager* tcp,uint32_t cur_ts,
                                    j_tcp_stream* cur_stream,const struct iphdr* iph,
                                    struct tcphdr* tcph,uint32_t seq,uint32_t ack_seq,
                                                        int payloadlen,uint16_t window){
    if(tcph->ack){
        if(TCP_SEQ_LEQ(ack_seq,cur_stream->snd->iss)
                || TCP_SEQ_GT(ack_seq,cur_stream->snd_nxt)){
            if(!tcph->rst){
                j_tcppkt_alone(tcp,iph->daddr,tcph->dest,iph->saddr,tcph->source,
                                            ack_seq,0,0,J_TCPHDR_RST,NULL,0,cur_ts,0);
            }
            return ;
        }
        cur_stream->snd->snd_una++;
    }

    if(tcph->rst && tcph->ack){
       cur_stream->state = J_TCP_CLOSE_WAIT;
       cur_stream->close_reason = TCP_RESET;
       if(cur_stream->s){
       }else{
           DestroyTcpStream(tcp,cur_stream);
       }
       return ;
    }
    if(tcph->syn && tcph->ack){
        int ret = j_tcp_active_open(tcp,cur_stream,cur_ts,tcph,seq,ack_seq,window);
        if(!ret){
            return ;
        }

        cur_stream->snd->nrtx = 0;
        cur_stream->rcv_nxt = cur_stream->rcv->irs + 1;
        RemoveFromRTOList(tcp,cur_stream);
        cur_stream->state = J_TCP_ESTABLISHED;

        j_trace_tcp("Stream %d:TCP_ST_ESTABLISHED.\n",cur_stream->id);

        if(cur_stream->s){
        }else{
            j_tcppkt_alone(tcp,iph->daddr,tcph->dest,iph->saddr,tcph->source,
                            0,seq + payloadlen + 1,0,J_TCPHDR_RST | J_TCPHDR_ACK,
                                                                    NULL,0,cur_ts,0);
            cur_stream->close_reason = TCP_ACTIVE_CLOSE;
            DestroyTcpStream(tcp,cur_stream);
        }
        j_tcp_addto_controllist(tcp,cur_stream);
        AddtoTimeoutList(tcp,cur_stream);
    }else{
        cur_stream->state = J_TCP_SYN_RCVD;
        cur_stream->snd_nxt = cur_stream->snd->iss;
        j_tcp_addto_controllist(tcp,cur_stream);
    }
}

static void j_tcp_handle_syn_rcvd(j_tcp_manager* tcp,uint32_t cur_ts,
                                  j_tcp_stream* cur_stream,struct tcphdr* tcph,
                                                                  uint32_t ack_seq){
    j_tcp_send* snd = cur_stream->snd;
    if(tcph->ack){
        if(ack_seq != snd->iss + 1){
            j_trace_tcp("Stream %d(TCP_ST_SYN_RCVD):"
                          "weird ack_seq:%u,iss:%u\n",
                           cur_stream->id,ack_seq,snd->iss);
            exit(1);
            return ;
        }
        snd->snd_una++;
        cur_stream->snd_nxt = ack_seq;
        uint32_t prior_cwnd = snd->cwnd;
        snd->cwnd = (prior_cwnd == 1) ? snd->mss * 2 : snd->mss;
        snd->nrtx = 0;

        //通过抓包，可以发现就是 TCP三次握手最后一次客户端向服务器返回的的ACK报文不会占用序列号
        //也就是ACK报文的序列号和接下来客户端向服务器发送的第一个数据包的序列号相同
        //j_trace_tcp("cur_stream->rcv->irs + 1 = %d\n",cur_stream->rcv->irs + 1);
        cur_stream->rcv_nxt = cur_stream->rcv->irs + 1; 
       
        //从超时队列中移除
        RemoveFromRTOList(tcp,cur_stream);

        cur_stream->state = J_TCP_ESTABLISHED;
        
        struct _j_tcp_listener* listener = ListenerHTSearch(tcp->listeners,&tcph->dest);
        //加入全连接队列中去
        int ret = StreamEnqueue(listener->acceptq,cur_stream);
        if(ret < 0){
            cur_stream->close_reason = TCP_NOT_ACCEPTED;
            cur_stream->state = J_TCP_CLOSED;
            j_tcp_addto_controllist(tcp,cur_stream);
        }

        //加入到保活队列里面去
        AddtoTimeoutList(tcp,cur_stream);

        j_trace_tcp("j_tcp_handle_syn_rcvd\n");
        if(listener->socket){
          //AddtoEpollEvent
#if J_ENABLE_EPOLL_RB
            if(tcp->ep){
                epoll_event_callback(tcp->ep,listener->socket->id,J_EPOLLIN);
            }
#else
            if(listener->socket->epoll && J_EPOLLIN){
                j_epoll_add_event(tcp->ep,J_EVENT_QUEUE,listener->s,J_EPOLLIN);
            }
#endif
            if(!(listener->socket->opts & J_TCP_NONBLOCK)){
                j_trace_tcp("j_tcp_flush_accept_event is called\n");
                //如果没有设置非阻塞的话
                j_tcp_flush_accept_event(listener);
            }
        }
    }else{
        j_trace_tcp("Stream %d (TCP_ST_SYN_RCVD):No ACK.\n",
                           cur_stream->id);
        cur_stream->snd_nxt = snd->iss;           //需要对SYN + ACK进行重传
        j_tcp_addto_controllist(tcp,cur_stream);
    }
}

void j_tcp_handle_established(j_tcp_manager* tcp,uint32_t cur_ts,
                               j_tcp_stream* cur_stream,struct tcphdr* tcph,
                               uint32_t seq,uint32_t ack_seq,uint8_t* payload,
                                                   int payloadlen,uint16_t window){
    if(tcph->syn){
        j_trace_tcp("Stream %d (TCP_ST_ESTABLISHED):weird SYN."
                      "seq:%u,excepted:%u,ack_seq:%u,expected:%u\n",
                      cur_stream->id,seq,cur_stream->rcv_nxt,ack_seq,cur_stream->snd_nxt);
        cur_stream->snd_nxt = ack_seq;
        j_tcp_addto_controllist(tcp,cur_stream);
        return ;
    }
    if(payloadlen > 0){
        if(j_tcp_process_payload(tcp,cur_stream,cur_ts,payload,seq,payloadlen)){
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_AGGREGATE);
        }else{
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_NOW);
        }
    }
    if(tcph->ack){
        if(cur_stream->snd->sndbuf){
            j_tcp_process_ack(tcp,cur_stream,cur_ts,
                                 tcph,seq,ack_seq,window,payloadlen);
        }
    }

    if(tcph->fin){
        if(seq + payloadlen == cur_stream->rcv_nxt){
            //按照这里的条件来看，该协议栈不允许fin报文携带数据
            cur_stream->state = J_TCP_CLOSE_WAIT;
            j_trace_tcp("Stream %d:TCP_ST_CLOSE_WAIT\n",cur_stream->id);
            cur_stream->rcv_nxt++;
            j_tcp_addto_controllist(tcp,cur_stream);
            //Read Event
            //j_trace_tcp("j_tcp_flush_read_event\n");
#if J_ENABLE_EPOLL_RB
            if(tcp->ep){
                epoll_event_callback(tcp->ep,cur_stream->s->id,J_EPOLLIN);
            }
            j_trace_tcp("epoll event_call:%d\n",cur_stream->socket->opts);
#endif
            if(cur_stream->socket && !(cur_stream->socket->opts & J_TCP_NONBLOCK)){
                //主要就是唤醒j_rcv.返回0
                j_tcp_flush_read_event(cur_stream->rcv);
            }
        }else{
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_NOW);
            return ;
        }
    }
    return ;
}

void j_tcp_handle_close_wait(j_tcp_manager* tcp,uint32_t cur_ts,
                             j_tcp_stream* cur_stream,struct tcphdr* tcph,
                             uint32_t seq,uint32_t ack_seq,int payloadlen,
                                                                 uint16_t window){
    if(TCP_SEQ_LT(seq,cur_stream->rcv_nxt)){
        j_trace_tcp("Stream %d (TCP_ST_CLOSE_WAIT):"
                      "weird seq:%u,expected:%u\n",
                      cur_stream->id,seq,cur_stream->rcv_nxt);
        j_tcp_addto_controllist(tcp,cur_stream);
        return ;
    }
    if(cur_stream->snd->sndbuf){
        //判断是否还有数据没发送完
        j_tcp_process_ack(tcp,cur_stream,cur_ts,tcph,seq,ack_seq,window,payloadlen);
    }
}

void j_tcp_handle_last_ack(j_tcp_manager* tcp,uint32_t cur_ts,const struct iphdr* iph,
                           int ip_len,j_tcp_stream* cur_stream,struct tcphdr* tcph,
                           uint32_t seq,uint32_t ack_seq,int payloadlen,uint16_t window){
    if(TCP_SEQ_LT(seq,cur_stream->rcv_nxt)){
        j_trace_tcp("Stream %d (TCP_ST_LAST_ACK):"
                      "werid seq:%u,excepted:%u\n",
                       cur_stream->id,seq,cur_stream->rcv_nxt);
        return ;
    }

    if(tcph->ack){
        if(cur_stream->snd->sndbuf){
           j_tcp_process_ack(tcp,cur_stream,cur_ts,tcph,seq,ack_seq,window,payloadlen);
        }
        if(!cur_stream->snd->is_fin_sent){
            j_trace_tcp("Stream %d (TCP_ST_LAST_ACK): "
                           "No FIN sent yet.\n",
                           cur_stream->id);
            return ;
        }
        if(ack_seq == cur_stream->snd->fss + 1){
            cur_stream->snd->snd_una++;
            //更新重传定时器
            UpdateRetransmissionTimer(tcp,cur_stream,cur_ts);

            cur_stream->state = J_TCP_CLOSED;
            cur_stream->close_reason = TCP_PASSIVE_CLOSE;
            j_trace_tcp("Stream %d: J_TCP_CLOSED\n",cur_stream->id);

            DestroyTcpStream(tcp,cur_stream);
        }else{
            j_trace_tcp("Stream %d (TCP_ST_LAST_ACK):Not ACK of FIN."
                          "ack_seq:%u,excepted:%u\n",
                          cur_stream->id,ack_seq,cur_stream->snd->fss + 1);
            j_tcp_addto_controllist(tcp,cur_stream);
        }
    }else{
        j_trace_tcp("Stream %d (TCP_ST_LAST_ACK):No ACK\n",
                      cur_stream->id);
        j_tcp_addto_controllist(tcp,cur_stream);
    }
}

void j_tcp_handle_fin_wait_1(j_tcp_manager* tcp,uint32_t cur_ts,
                                j_tcp_stream* cur_stream,struct tcphdr* tcph,
                                uint32_t seq,uint32_t ack_seq,
                                uint8_t* payload,int payloadlen,uint16_t window){
    if(TCP_SEQ_LT(seq,cur_stream->rcv_nxt)){
        //过期数据包
        j_trace_tcp("Stream %d (TCP_ST_LAST_ACK): "
                       "weird seq:%u,expected:%u\n",
                       cur_stream->id,seq,cur_stream->rcv_nxt);
        j_tcp_addto_controllist(tcp,cur_stream);
        return ;
    }

    if(tcph->ack){
        if(cur_stream->snd->sndbuf){
            //对sndbuf中的数据进行确认
            j_tcp_process_ack(tcp,cur_stream,cur_ts,tcph,seq,ack_seq,window,payloadlen);
        }

        if(cur_stream->snd->is_fin_sent &&
             ack_seq == cur_stream->snd->fss + 1){
            cur_stream->snd->snd_una = ack_seq;
            if(TCP_SEQ_GT(ack_seq,cur_stream->snd_nxt)){
                j_trace_tcp("Stream %d: update snd_nxt to %u\n",
                              cur_stream->id,ack_seq);
                cur_stream->snd_nxt = ack_seq;
            }
            cur_stream->snd->nrtx = 0;
            RemoveFromRTOList(tcp,cur_stream);
            cur_stream->state = J_TCP_FIN_WAIT_2;

            j_trace_tcp("Stream %u:TCP_ST_FIN_WAIT_2\n",
                          cur_stream->id);
        }
    }else{
        j_trace_tcp("Stream %u:does not contain an ack!\n",
                       cur_stream->id);
        return ;
    }

    if(payloadlen > 0){
        if(j_tcp_process_payload(tcp,cur_stream,cur_ts,payload,seq,payloadlen)){
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_AGGREGATE);
        }else{
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_AGGREGATE);
        }
    }

    if(tcph->fin){
        if(seq + payloadlen == cur_stream->rcv_nxt){
            cur_stream->rcv_nxt++;
            if(cur_stream->state == J_TCP_FIN_WAIT_1){ 
                cur_stream->state = J_TCP_CLOSING;
                j_trace_tcp("Stream %d: TCP_ST_CLOSING\n",cur_stream->id);
            }else if(cur_stream->state == J_TCP_FIN_WAIT_2){
                //这里感觉不太可能会进入到，所在的这个函数只有tcp stream在fin wait1的状态下才会被调用到
                //所以这里的fin wait2状态是不可能的
                cur_stream->state = J_TCP_TIMEWAIT;
                j_trace_tcp("Stream %d:TCP_ST_TIME_WAIT\n",cur_stream->id);
                AddtoTimewaitList(tcp,cur_stream,cur_ts);
            }else{
                assert(0);
            }
            j_tcp_addto_controllist(tcp,cur_stream);
        }
    }
}

void j_tcp_handle_fin_wait_2(j_tcp_manager* tcp,uint32_t cur_ts,j_tcp_stream* cur_stream,
                               struct tcphdr* tcph,uint32_t seq,uint32_t ack_seq,uint8_t* payload,int payloadlen,uint16_t  window){
    if(tcph->ack){
        if(cur_stream->snd->sndbuf){
            j_tcp_process_ack(tcp,cur_stream,cur_ts,tcph,
                               seq,ack_seq,window,payloadlen);
        }
    }else{
        j_trace_tcp("Stream %d:dose not contain an ack\n",
                       cur_stream->id);
        return ;
    }

    if(payloadlen > 0){
        if(j_tcp_process_payload(tcp,cur_stream,cur_ts,payload,seq,payloadlen)){
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_AGGREGATE);
        }else{
            j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_NOW);
        }
    }

    if(tcph->fin){
        if(seq + payloadlen == cur_stream->rcv_nxt){
            cur_stream->state = J_TCP_TIME_WAIT;
            cur_stream->rcv_nxt++;
            j_trace_tcp("Stream %d: TCP_ST_TIME_WAIT\n",cur_stream->id);

            AddtoTimewaitList(tcp,cur_stream,cur_ts);
            j_tcp_addto_controllist(tcp,cur_stream);
        }
    }
}

void j_tcp_handle_closing(j_tcp_manager* tcp,uint32_t cur_ts,j_tcp_stream* cur_stream,
                           struct tcphdr* tcph,uint32_t seq,uint32_t ack_seq,int payloadlen,
                           uint16_t window){
    if(tcph->ack){
        if(cur_stream->snd->sndbuf){
            j_tcp_process_ack(tcp,cur_stream,cur_ts,tcph,seq,ack_seq,window,payloadlen);
        }

        if(!cur_stream->snd->is_fin_sent){
            j_trace_tcp("Stream %d (TCP_ST_CLOSING):"
                          "No FIN sent yet.\n",cur_stream->id);
            return ;
        }
        if(ack_seq != cur_stream->snd->fss +1){
            return ;
        }

        cur_stream->snd->snd_una = ack_seq;
        cur_stream->snd_nxt = ack_seq;
        UpdateRetransmissionTimer(tcp,cur_stream,cur_ts);

        cur_stream->state = J_TCP_TIME_WAIT;
        j_trace_tcp("Stream %d: TCP_ST_TIME_WAIT\n",cur_stream->id);

        AddtoTimewaitList(tcp,cur_stream,cur_ts);
    }else{
        j_trace_tcp("Stream %d (TCP_ST_CLOSING):Not ACK\n",
                      cur_stream->id);
        return ;
    }
}

//计算出大致的rtt时间
void j_tcp_estimate_rtt(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t mrtt){
#define TCP_RTO_MIN  0

    long m = mrtt;
    uint32_t tcp_rto_min = TCP_RTO_MIN;
    j_tcp_recv* rcv = cur_stream->rcv;

    if(m == 0){
        m = 1;
    }
    if(rcv->srtt != 0){
        m -= (rcv->srtt >> 3);
        rcv->srtt += 3;
        if(m < 0){
            m = -m;
            m -= (rcv->mdev >> 2);
            if(m > 0){
                m >>= 3;
            }
        }else{
            m -= (rcv->mdev >> 2);
        }

        rcv->mdev += m;
        if(rcv->mdev >  rcv->mdev_max){
            rcv->mdev_max = rcv->mdev;
            if(rcv->mdev_max > rcv->rttvar){
                rcv->rttvar = rcv->mdev_max;
            }
        }

        if(TCP_SEQ_GT(cur_stream->snd->snd_una,rcv->rtt_seq)){
            if(rcv->mdev_max < rcv->rttvar){
                rcv->rttvar -= (rcv->rttvar - rcv->mdev_max) >> 2;
            }
            rcv->rtt_seq = cur_stream->snd_nxt;
            rcv->mdev_max = tcp_rto_min;
        }
    }else{
        //计算第一个RTT的测量值
        rcv->srtt = m << 3;
        rcv->mdev = m << 1;
        rcv->mdev_max = rcv->rttvar = MAX(rcv->mdev,tcp_rto_min);
        rcv->rtt_seq = cur_stream->snd_nxt;
    }
    j_trace_tcp("mrtt: %u (%uus), srtt: %u (%ums), mdev: %u, mdev_max: %u, "
            "rttvar: %u, rtt_seq: %u\n", mrtt, mrtt * TIME_TICK, 
            rcv->srtt, TS_TO_MSEC((rcv->srtt) >> 3), rcv->mdev, 
                rcv->mdev_max, rcv->rttvar, rcv->rtt_seq);
}

static int j_tcp_process_payload(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
                                 uint32_t cur_ts,uint8_t* payload,uint32_t seq,
                                 int payloadlen){
    j_tcp_recv* rcv = cur_stream->rcv;

    if(TCP_SEQ_LT(seq + payloadlen,cur_stream->rcv_nxt)){
        //这个数据包中的数据的都是旧数据
        return 0;
    }
    //seq + payloadlen -> seq
    if(TCP_SEQ_GT(seq,cur_stream->rcv_nxt + rcv->rcv_wnd)){
        //不应该那seq来判断吗
        return 0;
    }

    if(!rcv->recvbuf){
        j_trace_tcp("j_tcp_process_payload------------\n");
        rcv->recvbuf = RBInit(tcp->rbm_rcv,rcv->irs + 1);
        if(!rcv->recvbuf){
            cur_stream->state = J_TCP_CLOSED;
            cur_stream->close_reason = TCP_NO_MEM;
            j_trace_tcp("Raise Erro Event\n");
            return -1;
        }
    }

#if J_ENABLE_BLOCKING
    if(pthread_mutex_lock(&rcv->read_lock)){
        if(errno == EDEADLK){
            perror("ProcessTCPPayload:read lcok blocked\n");
        }
        assert(0);
    }
#else
    if(SBUF_LOCK(&rcv->read_lock)){
        if(errno == EDEADLK){
            perror("ProcessTCPPayload: read_lock blocked\n");
        }
        assert(0);
    }
#endif

    uint32_t prev_rcv_nxt = cur_stream->rcv_nxt;
    //将payload的数据放入到接收缓冲区中
    int ret = RBPut(tcp->rbm_rcv,rcv->recvbuf,payload,(uint32_t)payloadlen,seq);
    if(ret < 0){
        j_trace_tcp("Cannot merge payload.reason:%d\n",ret);
    }

    if(cur_stream->state == J_TCP_FIN_WAIT_1 ||
              cur_stream->state == J_TCP_FIN_WAIT_2){
        RBRemove(tcp->rbm_rcv,rcv->recvbuf,rcv->recvbuf->merged_len,AT_MTCP);
    }

    cur_stream->rcv_nxt = rcv->recvbuf->head_seq + rcv->recvbuf->merged_len;
    rcv->rcv_wnd = rcv->recvbuf->size - rcv->recvbuf->merged_len;

#if J_ENABLE_BLOCKING
    pthread_mutex_unlock(&rcv->read_lock);
#else
    SBUF_UNLOCK(&rcv->read_lock);
#endif

    if(TCP_SEQ_LEQ(cur_stream->rcv_nxt,prev_rcv_nxt)){
        return 0;
    }

    if(cur_stream->state == J_TCP_ESTABLISHED){
        //由于收到的数据，所以会触发读事件
        if(cur_stream->socket){
#if J_ENABLE_EPOLL_RB
            if(tcp->ep){
                epoll_event_callback(tcp->ep,cur_stream->s->id,J_EPOLLIN);
            }
#else
            j_epoll_add_event(tcp->ep,J_EVENT_QUEUE,cur_stream->s,J_EPOLLIN);
#endif
            if(!(cur_stream->socket->opts & J_TCP_NONBLOCK)){
                j_tcp_flush_read_event(rcv);
            }
        }
    }
    return 1;
}
static int j_tcp_process_rst(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t ack_seq){
    j_trace_tcp("Stream %d TCP_RESET (%d)\n",
                  cur_stream->id,cur_stream->state);

    if(cur_stream->state <= J_TCP_SYN_SENT){
        return 0;
    }

    if(cur_stream->state == J_TCP_SYN_RCVD){
        if(ack_seq == cur_stream->snd_nxt){
            cur_stream->state = J_TCP_CLOSED;
            cur_stream->close_reason = TCP_RESET;
            DestroyTcpStream(tcp,cur_stream);
        }
        return 1;
    }

    if(cur_stream->state == J_TCP_FIN_WAIT_1 || 
              cur_stream->state == J_TCP_FIN_WAIT_2 ||
              cur_stream->state == J_TCP_LAST_ACK ||
              cur_stream->state == J_TCP_CLOSING ||
              cur_stream->state == J_TCP_TIME_WAIT){
        cur_stream->state = J_TCP_CLOSED;
        cur_stream->close_reason = TCP_ACTIVE_CLOSE;
        DestroyTcpStream(tcp,cur_stream);
        return 1;
    }

    if(cur_stream->state >= J_TCP_ESTABLISHED && 
            cur_stream->state <= J_TCP_CLOSE_WAIT){
        j_trace_tcp("Stream %d:Notifying connection reset.\n",cur_stream->id);
    }

    if(!(cur_stream->snd->on_closeq || 
           cur_stream->snd->on_closeq_int ||
           cur_stream->snd->on_resetq || 
           cur_stream->snd->on_resetq_int)){
        cur_stream->state = J_TCP_CLOSE_WAIT;
        cur_stream->close_reason = TCP_RESET;
    }

    return 1;
}

static void j_tcp_process_ack(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t cur_ts,
                                  struct tcphdr* tcph,uint32_t seq,uint32_t ack_seq,
                                      uint16_t window,int payloadlen){
    j_tcp_send* snd = cur_stream->snd;
    uint32_t cwindow = window;

    if(!tcph->syn){
        //计算出真实的接收方接收窗口的大小
        cwindow = cwindow << snd->wscale_peer;
    }

    //对方接收窗口的有边界
    uint32_t right_wnd_edge = snd->peer_wnd + cur_stream->rcv->snd_wl1;
    if(cur_stream->state == J_TCP_FIN_WAIT_1 || 
            cur_stream->state == J_TCP_FIN_WAIT_2 ||
            cur_stream->state == J_TCP_CLOSING ||
            cur_stream->state == J_TCP_CLOSE_WAIT || 
            cur_stream->state == J_TCP_LAST_ACK){
        if(snd->is_fin_sent && ack_seq == snd->fss + 1){
            ack_seq--;
        }
    }
    if(TCP_SEQ_GT(ack_seq,snd->sndbuf->head_seq + snd->sndbuf->len)){
        //seq + payloadlen = ack_seq
        j_trace_tcp("Stream %d(%d): invalid ack.ack_seq: %u,max_ack_seq: %u\n",
                       cur_stream->id,cur_stream->state,ack_seq,snd->sndbuf->head_seq + snd->sndbuf->len);
        return ;
    }

    //更新发送窗口
    uint32_t cwindow_prev;
    if(TCP_SEQ_LT(cur_stream->rcv->snd_wl1,seq) ||  
            (cur_stream->rcv->snd_wl1 == seq && 
              TCP_SEQ_LT(cur_stream->rcv->snd_wl2,ack_seq)) ||
            (cur_stream->rcv->snd_wl2 == ack_seq && 
              cwindow >snd->peer_wnd)){
        cwindow_prev = snd->peer_wnd;
        snd->peer_wnd = window;
        cur_stream->rcv->snd_wl1 = seq;
        cur_stream->rcv->snd_wl2 = ack_seq;

        if(cwindow_prev < (cur_stream->snd_nxt - cur_stream->snd->snd_una) &&
                snd->peer_wnd >= (cur_stream->snd_nxt - cur_stream->snd->snd_una)){
            j_trace_tcp("Stream %u Broadcasting client window update!"
                          "ack_seq: %u,peer_wnd:%u (before:%u),"
                           "(snd_nxt - snd_una:%u)\n",
                            cur_stream->id,ack_seq,snd->peer_wnd,cwindow_prev,
                             cur_stream->snd_nxt - snd->snd_una);
            j_tcp_flush_send_event(snd);
        }
    }

    //和快速重传有关
    uint8_t dup = 0;
    if(TCP_SEQ_LT(ack_seq,cur_stream->snd_nxt)){
        if(ack_seq == cur_stream->rcv->last_ack_seq && payloadlen == 0){
            if(cur_stream->rcv->snd_wl2 + snd->peer_wnd == right_wnd_edge){
                if(cur_stream->rcv->dup_acks + 1 > cur_stream->rcv->dup_acks){
                    cur_stream->rcv->dup_acks++;
                }
                dup = 1;
            }
        }
    }

    if(!dup){
        cur_stream->rcv->dup_acks = 0;
        cur_stream->rcv->last_ack_seq = ack_seq;
    }

    if(dup && cur_stream->rcv->dup_acks == 3){
        //快重传
        j_trace_tcp("Triple duplicated ACKs!.ack_seq:%u\n",ack_seq);
        if(TCP_SEQ_LT(ack_seq,cur_stream->snd_nxt)){
            j_trace_tcp("Reducing snd_nxt from %u to %u\n",
                          cur_stream->snd_nxt,ack_seq);
            if(ack_seq != snd->snd_una){
                j_trace_tcp("ack_seq and snd_una mismatch on tdp ack."
                               "ack_seq:%u,snd_una:%u\n",
                                 ack_seq,snd->snd_una);
            }
            cur_stream->snd_nxt = ack_seq;
        }

        snd->ssthresh = MIN(snd->cwnd,snd->peer_wnd) / 2;
        if(snd->ssthresh < 2 * snd->mss){
            snd->ssthresh = 2 * snd->mss;
        }

        //快速恢复算法
        snd->cwnd = snd->ssthresh + 3 * snd->mss;
        j_trace_tcp("Fast retransmission.cwnd:%u,ssthresh:%u\n",
                          snd->cwnd,snd->ssthresh);

        if(snd->nrtx < TCP_MAX_RTX){
            snd->nrtx++;
        }else{
            j_trace_tcp("Exceed MAX_RTX.\n");
        }
        //根据当前信息进行重传
        j_tcp_addto_sendlist(tcp,cur_stream);
    }else if(cur_stream->rcv->dup_acks > 3){
        //代表重传失败，cwnd + 1，然后继续进行重传
        if((uint32_t)(snd->cwnd + snd->mss) > snd->cwnd){
            snd->cwnd += snd->mss;
            j_trace_tcp("Dupack cwnd in flate.cwnd:%u ,ssthresh:%u\n",
                          snd->cwnd,snd->ssthresh);
        }
    }

    if(TCP_SEQ_GT(ack_seq,cur_stream->snd_nxt)){
        j_trace_tcp("Updating snd_nxt from %u to %u\n",
                       cur_stream->snd_nxt,ack_seq);
        cur_stream->snd_nxt = ack_seq;
        if(snd->sndbuf->len == 0){
            j_tcp_remove_sendlist(tcp,cur_stream);
        }
    }

    if(TCP_SEQ_GEQ(snd->sndbuf->head_seq,ack_seq)){
        //发送缓冲区没有要确认的数据.
        return ;
    }

    uint32_t rmlen = ack_seq - snd->sndbuf->head_seq;
    if(rmlen > 0){
        uint16_t packets = rmlen / snd->eff_mss;
        if((rmlen / snd->eff_mss) * snd->eff_mss > rmlen){
            packets++;
        }
        if(cur_stream->saw_timestamp){
            //更新rtt和rto
            j_tcp_estimate_rtt(tcp,
                            cur_stream,cur_ts - cur_stream->rcv->ts_lastack_rcvd);
            snd->rto = (cur_stream->rcv->srtt >> 3) + cur_stream->rcv->rttvar;
            assert(snd->rto > 0);
        }else{
            j_trace_tcp("not implemented.\n");
        }

        if(cur_stream->state >= J_TCP_ESTABLISHED){
            if(snd->cwnd < snd->ssthresh){
                if((snd->cwnd + snd->mss) > snd->cwnd){
                    //还处于慢启动状态
                    snd->cwnd += snd->mss * packets;
                }
                j_trace_tcp("slow start cwnd:%u,ssthresh:%u\n",
                              snd->cwnd,snd->ssthresh); 
            }
        }else{
            //疑似拥塞避免算法
            uint32_t new_cwnd = snd->cwnd + packets * snd->mss * snd->mss / snd->cwnd;
            if(new_cwnd > snd->cwnd){
                snd->cwnd = new_cwnd;
            }
        }

        if(pthread_mutex_lock(&snd->write_lock)){
            if(errno == EDEADLK){
                perror("ProcessACK: write_lcok blocked\n");
            }
            assert(0);
        }

        //从发送缓冲区中移除已经确认过的数据
        int ret = SBRemove(tcp->rbm_snd,snd->sndbuf,rmlen);
        if(ret < 0){
            return ;
        }

        snd->snd_una = ack_seq;
        uint32_t snd_wnd_prev = snd->snd_wnd;
        snd->snd_wnd = snd->sndbuf->size - snd->sndbuf->len;

        if(snd_wnd_prev <= 0){
            j_tcp_flush_send_event(snd);
        }

        pthread_mutex_unlock(&snd->write_lock);
        UpdateRetransmissionTimer(tcp,cur_stream,cur_ts);
    }
}


//传输层的入口函数
int j_tcp_process(j_nic_context* ctx,unsigned char* stream){
    struct iphdr* iph = (struct iphdr*)(stream + sizeof(struct ethhdr));
    struct tcphdr* tcph = (struct tcphdr*)(stream + sizeof(struct ethhdr) + sizeof(struct iphdr));
    //验证ip首部长度是否和记录的一样大,这里ip header上中记录的长度都是具体长度 / 4 之后的
    assert(sizeof(struct iphdr) == (iph->ihl << 2));

    int ip_len = ntohs(iph->tot_len);
    uint8_t* payload = (uint8_t*)tcph + (tcph->doff << 2); //携带的负载数据的起始位置
    //tcp报文的长度
    int tcp_len = ip_len - (iph->ihl << 2);
    //收到的数据部分的长度
    int payloadlen = tcp_len - (tcph->doff << 2);

    unsigned short check = j_tcp_calculate_checksum((uint16_t*)tcph,tcp_len,iph->saddr,iph->daddr);
    j_trace_tcp("check : %x,origin : %x,payloadlen: %d\n",check,tcph->check,payloadlen);
    if(check){
        return 1;
    }

    j_tcp_stream tstream = {0};
    tstream.saddr = iph->daddr;
    tstream.daddr = iph->saddr;
    tstream.sport = tcph->dest;
    tstream.dport  = tcph->source;
#if 0
    j_trace_tcp("iph->daddr = 0x%x,tcph->dest = %d\n",iph->daddr,ntohs(tcph->dest));
#endif

    struct timeval cur_ts = {0};
    gettimeofday(&cur_ts,NULL);

    uint32_t ts = TIMEVAL_TO_TS(&cur_ts);
    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack_seq = ntohl(tcph->ack_seq);
    uint16_t window = ntohs(tcph->window);

    j_trace_tcp("saddr:0x%x,sport:%d,daddr:0x%x,dport:%d,seq:%d,ack_seq:%d\n",
                  iph->daddr,ntohs(tcph->dest),iph->saddr,ntohs(tcph->source),seq,ack_seq);

    j_tcp_stream* cur_stream = (j_tcp_stream*)StreamHTSearch(j_tcp->tcp_flow_table,&tstream);
    if(cur_stream == NULL){
        cur_stream = j_create_stream(j_tcp,ts,iph,ip_len,tcph,seq,ack_seq,payloadlen,window);
        if(!cur_stream){
            return -2;
        }
    }

    int ret = 0;
    if(cur_stream->state > J_TCP_SYN_RCVD){
        //判断序列号是否有问题
        //j_trace_tcp("j_tcp_validseq is called,cur_stream->rcv_nxt = %d,seq = %d \n",cur_stream->rcv_nxt,seq);
        ret = j_tcp_validseq(j_tcp,cur_stream,ts,tcph,seq,ack_seq,payloadlen);
        if(!ret){
            j_trace_tcp("Stream %d: Unpected sequence :%u,expected:%u\n",
                          cur_stream->id,seq,cur_stream->rcv_nxt);
            return 1;
        }
    }

    j_trace_tcp("j_tcp_process state:%d\n",cur_stream->state);

    if(tcph->syn){
        cur_stream->snd->peer_wnd = window;
    }else{
        cur_stream->snd->peer_wnd = (uint32_t)window << cur_stream->snd->wscale_peer;
    }

    cur_stream->last_active_ts = ts;
    UpdateTimeoutList(j_tcp,cur_stream);

    if(tcph->rst){
        cur_stream->have_reset = 1;
        if(cur_stream->state > J_TCP_SYN_SENT){
            if(j_tcp_process_rst(j_tcp,cur_stream,ack_seq)){
                return 1;
            }
        }
    }

    switch(cur_stream->state){
        case J_TCP_LISTEN:
            j_tcp_handle_listen(j_tcp,ts,cur_stream,tcph);
            break;
        case J_TCP_SYN_SENT:
            j_tcp_handle_syn_sent(j_tcp,ts,cur_stream,iph,tcph,seq,ack_seq,payloadlen,window);
            break;
        case J_TCP_SYN_RCVD:
            {
                if(tcph->syn && seq == cur_stream->rcv->irs){
                    //处理重传的SYN报文
                    j_tcp_handle_listen(j_tcp,ts,cur_stream,tcph);
                }else{
                    j_tcp_handle_syn_rcvd(j_tcp,ts,cur_stream,tcph,ack_seq);
                    //j_trace_tcp("cur_stream->rcv_nxt = %d\n",cur_stream->rcv_nxt);
                    if(payloadlen > 0 && cur_stream->state == J_TCP_ESTABLISHED){
                        j_tcp_handle_established(j_tcp,ts,cur_stream,tcph,seq,ack_seq,payload,payloadlen,window);
                    }
                }
                break;
            }
        case J_TCP_ESTABLISHED:
            j_tcp_handle_established(j_tcp,ts,cur_stream,tcph,seq,ack_seq,payload,payloadlen,window);
            break;
        case J_TCP_CLOSE_WAIT:
            j_tcp_handle_close_wait(j_tcp,ts,cur_stream,tcph,seq,ack_seq,payloadlen,window);
            break;
        case J_TCP_LAST_ACK:
            j_tcp_handle_last_ack(j_tcp,ts,iph,ip_len,cur_stream,tcph,seq,ack_seq,payloadlen,window);
            break;
        case J_TCP_FIN_WAIT_1:
            j_tcp_handle_fin_wait_1(j_tcp,ts,cur_stream,tcph,seq,ack_seq,payload,payloadlen,window);
            break;
        case J_TCP_FIN_WAIT_2:
            j_tcp_handle_fin_wait_2(j_tcp,ts,cur_stream,tcph,seq,ack_seq,payload,payloadlen,window);
            break;
        case J_TCP_CLOSING:
            j_tcp_handle_closing(j_tcp,ts,cur_stream,tcph,seq,ack_seq,payloadlen,window);
            break;
        case J_TCP_TIME_WAIT:
            {
                if(cur_stream->on_timewait_list){
                    RemoveFromTimewaitList(j_tcp,cur_stream);
                    AddtoTimewaitList(j_tcp,cur_stream,ts);
                }
                j_tcp_addto_controllist(j_tcp,cur_stream);
                break;
            }
        case J_TCP_CLOSED:
            break;
    }
    return 1;
}

j_sender* j_tcp_create_sender(int ifidx){
    j_sender* sender = (j_sender*)calloc(1,sizeof(j_sender));
    if(!sender){
        return NULL;
    }

    sender->ifidx = ifidx;
    TAILQ_INIT(&sender->control_list);
    TAILQ_INIT(&sender->send_list);
    TAILQ_INIT(&sender->ack_list);

    sender->control_list_cnt = 0;
    sender->send_list_cnt = 0;
    sender->ack_list_cnt = 0;

    return sender;
}

void j_tcp_destroy_sender(j_sender* sender){
    free(sender);
}

int j_tcp_init_manager(j_thread_context* ctx){
    j_tcp_manager* tcp = (j_tcp_manager*)calloc(1,sizeof(j_tcp_manager));
    if(!tcp){
        perror("calloc j_tcp_manager error");
        return -1;
    }

    tcp->tcp_flow_table = CreateHashtable(HashFlow,EqualFlow,NUM_BINS_FLOWS);
    if(!tcp->tcp_flow_table){
        j_trace_tcp("[%s:%s:%d] -- > create hash table\n",__FILE__,__func__,__LINE__);
        return -2;
    }

    tcp->listeners = CreateHashtable(HashListener,EqualListener,NUM_BINS_LISTENERS);
    if(!tcp->listeners){
        j_trace_tcp("[%s:%s:%d] -- > create hash table\n",__FILE__,__func__,__LINE__);
        return -2;
    }

#ifdef HUGEPAGE
#define IS_HUGEPAGE   1
#else
#define IS_HUGEPAGE   0
#endif

    tcp->flow = j_mempool_create(sizeof(j_tcp_stream),sizeof(j_tcp_stream) * 
                                                     J_MAX_CONCURRENCY,IS_HUGEPAGE);
    if(!tcp->flow){
        j_trace_tcp("Failed to allocate tcp flow pool\n");
        return -3;
    }

    tcp->rcv = j_mempool_create(sizeof(j_tcp_recv),sizeof(j_tcp_recv) * 
                                                    J_MAX_CONCURRENCY,IS_HUGEPAGE);
    if(!tcp->rcv){
        j_trace_tcp("Failed to allocate tcp recv pool\n");
        return -3;
    }


    tcp->snd = j_mempool_create(sizeof(j_tcp_send),sizeof(j_tcp_send) * 
                                                   J_MAX_CONCURRENCY,IS_HUGEPAGE);
    if(!tcp->snd){
        j_trace_tcp("Failed to allocate tcp send pool\n");
        return -3;
    }


    tcp->rbm_snd = j_sbmanager_create(J_SNDBUF_SIZE,J_MAX_NUM_BUFFERS);
    if(!tcp->rbm_snd){
        j_trace_tcp("Failed to create send ring buffer\n");
        return -4;
    }
    tcp->rbm_rcv = RBManagerCreate(J_RCVBUF_SIZE,J_MAX_NUM_BUFFERS);
    if(!tcp->rbm_rcv){
        j_trace_tcp("Failed to create recv ring buffer\n");
        return -4;
    }
    InitialTCPStreamManager();

#if J_ENABLE_SOCKET_C10M
    tcp->fdtable = j_socket_init_fdtable();
    if(!tcp->fdtable){
        j_trace_tcp("Failed to create fdtable.\n");
        return -4;
    }
#endif

    tcp->smap = (j_socket_map*)calloc(J_MAX_CONCURRENCY,sizeof(j_socket_map));
    if(!tcp->smap){
        j_trace_tcp("Failed to allocate memory for stream map.\n");
        return -5;
    }

    TAILQ_INIT(&tcp->free_smap);

    int i = 0;
    for(;i < J_MAX_CONCURRENCY;++i){
        tcp->smap[i].id = i;
        tcp->smap[i].socktype = J_TCP_SOCK_UNUSED;
        memset(&tcp->smap[i].s_addr,0,sizeof(struct sockaddr_in));
        tcp->smap[i].stream = NULL;
        TAILQ_INSERT_TAIL(&tcp->free_smap,&tcp->smap[i],free_smap_link);
    }

    tcp->ctx = ctx;

    tcp->connectq = CreateStreamQueue(J_BACKLOG_SIZE);
    if(!tcp->connectq){
        j_trace_tcp("Failed to create connect queue.\n");
        return -6;
    }

    tcp->sendq = CreateStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->sendq){
        j_trace_tcp("Failed to create send queue.\n");
        return -6;
    }

    tcp->ackq = CreateStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->ackq){
        j_trace_tcp("Failed to create ack queue.\n");
        return -6;
    }

    tcp->closeq = CreateStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->closeq){
        j_trace_tcp("Failed to create closeq queue.\n");
        return -6;
    }

    tcp->closeq_int = CreateInternalStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->closeq_int){
        j_trace_tcp("Failed to create close_int queue.\n");
        return -6;
    }

    tcp->resetq = CreateStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->resetq){
        j_trace_tcp("Failed to create reset queue.\n");
        return -6;
    }

    tcp->resetq_int = CreateInternalStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->resetq_int){
        j_trace_tcp("Failed to create reset_int queue.\n");
        return -6;
    }

    tcp->destroyq = CreateStreamQueue(J_MAX_CONCURRENCY);
    if(!tcp->destroyq){
        j_trace_tcp("Failed to create destroy queue.\n");
        return -6;
    }

    tcp->g_sender = j_tcp_create_sender(-1);
    if(!tcp->g_sender){
        j_trace_tcp("Failed to create global sender structure.\n");
        return -7;
    }

    for(i = 0;i < ETH_NUM;++i){
        tcp->n_sender[i] = j_tcp_create_sender(i);
        if(!tcp->n_sender[i]){
            j_trace_tcp("Failed to create sender structure.\n");
            return -7;
        }
    }

    tcp->rto_store = InitRTOHashstore();

    TAILQ_INIT(&tcp->timewait_list);
    TAILQ_INIT(&tcp->timeout_list);

#if J_ENABLE_BLOCKING
    TAILQ_INIT(&tcp->rcv_br_list);
    TAILQ_INIT(&tcp->snd_br_list);
#endif

    j_tcp = tcp;

    return 0;
}

void j_tcp_init_thread_context(j_thread_context* ctx){
    assert(ctx != NULL);

    ctx->cpu = 0;
    ctx->thread = pthread_self();

    j_tcp_init_manager(ctx);

    if(pthread_mutex_init(&ctx->smap_lock,NULL)){
        j_trace_tcp("pthread_mutex_init of ctx->smap_lock.\n");
        exit(-1);
    }

    if(pthread_mutex_init(&ctx->flow_pool_lock,NULL)){
        j_trace_tcp("pthread_mutex_init of ctx->flow_pool_lock.\n");
        exit(-1);
    }

    if(pthread_mutex_init(&ctx->socket_pool_lock,NULL)){
        j_trace_tcp("pthread_mutex_init of ctx->socket_pool_lock.\n");
        exit(-1);
    }
}

//该函数其实就是对当前tcp manager中各个queue中的stream进行处理
int j_tcp_handle_apicall(uint32_t cur_ts){
    j_tcp_manager* tcp = j_get_tcp_manager();
    assert(tcp != NULL);

    j_tcp_stream* stream = NULL;
    while((stream = StreamDequeue(tcp->connectq))){
        j_tcp_addto_controllist(tcp,stream);
    }

    //从tcp manager的sendq中移除，然后加入到sennder的send_list里面去
    while((stream = StreamDequeue(tcp->sendq))){
        j_trace_tcp("buf:%s,mss:%d\n",stream->snd->sndbuf->data,stream->snd->mss);
        stream->snd->on_sendq = 0;
        j_tcp_addto_sendlist(tcp,stream);
    }

    //从ackq中移除，加入到ack list上面去
    while((stream = StreamDequeue(tcp->ackq))){
        stream->snd->on_ackq = 0;
        j_tcp_enqueue_acklist(tcp,stream,cur_ts,ACK_OPT_AGGREGATE);
    }

    int handled = 0;
    int delayed = 0;
    int control = 0;
    int send = 0;
    int ack = 0;

    while((stream = StreamDequeue(tcp->closeq))){
        j_tcp_send* snd = stream->snd;
        snd->on_closeq = 0;

        if(snd->sndbuf){
            snd->fss = snd->sndbuf->head_seq + snd->sndbuf->len;
        }else{
            snd->fss = stream->snd_nxt;
        }

        RemoveFromTimeoutList(tcp,stream);

        if(stream->have_reset){
            handled++;
            if(stream->state != J_TCP_CLOSED){
                stream->close_reason = TCP_RESET;
                stream->state = J_TCP_CLOSED;

                j_trace_tcp("Stream %d: TCP_ST_CLOSED\n",stream->id);
                DestroyTcpStream(tcp,stream);
            }else{
                j_trace_tcp("Stream already closed.\n");
            }
        }else if(snd->on_control_list){
            snd->on_closeq_int = 1;
            StreamInternalEnqueue(tcp->closeq_int,stream);
            delayed++;  //延迟处理的+1

            if(snd->on_control_list){
                control++;
            }
            if(snd->on_send_list){
                send++;
            }
            if(snd->on_ack_list){
                ack++;
            }
        }else if(snd->on_send_list || snd->on_ack_list){
            handled++;
            if(stream->state == J_TCP_ESTABLISHED){
                stream->state = J_TCP_FIN_WAIT_1;
                j_trace_tcp("Stream %d:J_TCP_FIN_WAIT_1\n",stream->id);
            }else if(stream->state == J_TCP_CLOSE_WAIT){
                stream->state = J_TCP_LAST_ACK;
                j_trace_tcp("Stream %d:J_TCP_LAST_ACK\n",stream->id);
            }
            stream->control_list_waiting = 1;
        }else if(stream->state != J_TCP_CLOSED){
            handled++;
            if(stream->state == J_TCP_ESTABLISHED){
                stream->state = J_TCP_FIN_WAIT_1;
                j_trace_tcp("Stream %d:J_TCP_FIN_WAIT_1.\n",stream->id);
            }else if(stream->state == J_TCP_CLOSE_WAIT){
                stream->state = J_TCP_LAST_ACK;
                j_trace_tcp("Stream %d:J_TCP_LAST_ACK.\n",stream->id);
            }
            j_tcp_addto_controllist(tcp,stream);
        }else{
            j_trace_tcp("Already closed connection! \n");
        }
    }

    while((stream = StreamDequeue(tcp->resetq))){
        stream->snd->on_resetq = 0;

        RemoveFromTimeoutList(tcp,stream);

        if(stream->have_reset){
            if(stream->state != J_TCP_CLOSED){
                stream->state = J_TCP_CLOSED;
                stream->close_reason = TCP_RESET;
                j_trace_tcp("Stream %d:TCP_ST_CLOSED\n",stream->id);
                DestroyTcpStream(tcp,stream);
            }else{
                j_trace_tcp("Stream already closed!\n");
            }
        }else if(stream->snd->on_control_list || 
                    stream->snd->on_send_list || 
                    stream->snd->on_ack_list){
            //延迟处理
            stream->snd->on_resetq_int = 1;
            StreamInternalEnqueue(tcp->resetq_int,stream);
        }else{
            if(stream->state != J_TCP_CLOSED){
                stream->state = J_TCP_CLOSED;
                stream->close_reason = TCP_ACTIVE_CLOSE;
                j_trace_tcp("Stream %d:TCP_ST_CLOSED.\n",stream->id);
                j_tcp_addto_controllist(tcp,stream);
            }else{
                j_trace_tcp("Stream already closed.\n");
            }
        }
    }

    int cnt = 0;
    int max_cnt = tcp->resetq_int->count;

    while(cnt++ < max_cnt){
        stream = StreamInternalDequeue(tcp->resetq_int);

        if(stream->snd->on_control_list 
                 || stream->snd->on_send_list 
                 || stream->snd->on_ack_list){
            StreamInternalEnqueue(tcp->resetq_int,stream);
        }else{
            stream->snd->on_resetq_int = 0;

            if(stream->state != J_TCP_CLOSED){
                stream->state = J_TCP_CLOSED;
                stream->close_reason = TCP_ACTIVE_CLOSE;
                j_trace_tcp("Stream %d:J_TCP_CLOSED.\n",stream->id);
                j_tcp_addto_controllist(tcp,stream);
            }else{
                j_trace_tcp("Stream already closed.\n");
            }
        }
    }

    while((stream = StreamDequeue(tcp->destroyq))){
        DestroyTcpStream(tcp,stream);
    }
    if(stream != NULL){
        j_trace_tcp("j_tcp_handle_apicall-->state %d\n",stream->state);
    }

    tcp->wakeup_flag = 0;

    return 0;
}

int j_tcp_flush_sendbuffer(j_tcp_stream* cur_stream,uint32_t cur_ts){
    j_tcp_manager* tcp = j_get_tcp_manager();
    assert(tcp != NULL);

    j_tcp_send* snd = cur_stream->snd;
    if(!snd->sndbuf){
        j_trace_tcp("Stream %d:No send buffer avaliable.\b",cur_stream->id);
        assert(0);
        return 0;
    }

    pthread_mutex_lock(&snd->write_lock);
    int packets = 0;

    if(snd->sndbuf->len == 0){
        //发送缓冲区内没有数据可以发送
        packets = 0;
        goto out;
    }

    uint32_t window = MIN(snd->cwnd,snd->peer_wnd); //发送窗口的大小
    uint32_t seq = 0;
    uint32_t buffered_len = 0;
    uint8_t* data = NULL;
    //option是算到data的长度里面的
    uint32_t maxlen = snd->mss - j_calculate_option(J_TCPHDR_ACK);
    uint16_t len = 0;       //发送的数据的大小
    uint8_t wack_sent = 0;
    int16_t sndlen = 0;

    while(1){
        seq = cur_stream->snd_nxt;
        if(TCP_SEQ_LT(seq,snd->sndbuf->head_seq)){
            //发送缓冲区中没有要发送的数据
            j_trace_tcp("Stream %d:Invalid sequence to send."
                           "state:%d, seq:%u,head_seq:%u.\n",
                            cur_stream->id,cur_stream->state,
                            seq,snd->sndbuf->head_seq);
            assert(0);
            break;
        }

        //发送缓冲区中从seq开始的数据的长度
        buffered_len = snd->sndbuf->head_seq + snd->sndbuf->len - seq;
        if(cur_stream->state == J_TCP_ESTABLISHED){
            j_trace_tcp("head_seq:%u ,len:%u ,seq:%u,"
                          "buffered_len:%u,mss:%d,cur_mss:%d\n",
                           snd->sndbuf->head_seq,snd->sndbuf->len,seq,buffered_len,
                           snd->mss,cur_stream->snd->mss);
        }
        if(buffered_len == 0){
            break;
        }

        data = snd->sndbuf->head + (seq - snd->sndbuf->head_seq);
        if(buffered_len > maxlen){
            len = maxlen;
        }else{
            len = buffered_len;
        }

        if(len > window){
            len = window;
        }

        if(len <= 0){
            break;
        }

        if(cur_stream->state > J_TCP_ESTABLISHED){
            j_trace_tcp("Flushing after ESTABLISHED: seq :%u,"
                             "len:%u,buffered_len:%u\n",
                             seq,len,buffered_len);
        }

        if(seq - snd->snd_una + len > window){
            if(seq - snd->snd_una + len > snd->peer_wnd){
                if(!wack_sent && TS_TO_MSEC(cur_ts - snd->ts_lastack_sent) > 500){
                    j_tcp_enqueue_acklist(tcp,cur_stream,cur_ts,ACK_OPT_WACK);
                }else{
                    wack_sent = 1;
                }
            }
            packets = -3;
            goto out;
        }

        sndlen = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,data,len);
        if(sndlen < 0){
            packets = sndlen;
            goto out;
        }
        packets++;

        j_trace_tcp("window:%d,len:%d\n",window,len);
        window -= len;
    }
out:
    pthread_mutex_unlock(&snd->write_lock);

    return packets;
}

//该函数就是用来对control_list中的stream来进行处理的
int j_tcp_send_controlpkt(j_tcp_stream* cur_stream,uint32_t cur_ts){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    j_tcp_send* snd = cur_stream->snd;

    int ret = 0;

    if(cur_stream->state == J_TCP_SYN_SENT){
        ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_SYN,NULL,0);
    }else if(cur_stream->state == J_TCP_SYN_RCVD){
        //j_trace_tcp("return SYN + ACK packet\n");
        cur_stream->snd_nxt = snd->iss;
        ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_SYN | J_TCPHDR_ACK,NULL,0);
    }else if(cur_stream->state == J_TCP_ESTABLISHED){
        ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,NULL,0);
    }else if(cur_stream->state == J_TCP_CLOSE_WAIT){
        ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,NULL,0);
    }else if(cur_stream->state == J_TCP_LAST_ACK){
        if(snd->on_send_list || snd->on_ack_list){
            ret = -1;
        }else{
            ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_FIN | J_TCPHDR_ACK,NULL,0);
        }
    }else if(cur_stream->state == J_TCP_FIN_WAIT_1){
        if(snd->on_send_list || 
                 snd->on_ack_list){
            ret = -1;
        }else{
            ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_FIN | J_TCPHDR_ACK,NULL,0);
        }
    }else if(cur_stream->state == J_TCP_FIN_WAIT_2){
        ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,NULL,0);
    }else if(cur_stream->state == J_TCP_CLOSING){
        if(snd->is_fin_sent){
            if(cur_stream->snd_nxt == snd->fss){
                ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_FIN | J_TCPHDR_ACK,
                                         NULL,0);
            }else{
                ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,NULL,0);
            }
        }else{
            ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_FIN | J_TCPHDR_ACK,NULL,0);
        }
    }else if(cur_stream->state == J_TCP_TIME_WAIT){
        ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,NULL,0);
    }else if(cur_stream->state == J_TCP_CLOSED){
        if(snd->on_send_list || snd->on_ack_list){
            ret = -1;
        }else{
            ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_RST,NULL,0);
            if(ret >= 0){
                DestroyTcpStream(tcp,cur_stream);
            }
        }
    }

    return ret;
}

//对control_list中的tcp stream进行处理
int j_tcp_write_controllist(j_sender* sender,uint32_t cur_ts,int thresh){
    thresh = MIN(thresh,sender->control_list_cnt);

    j_tcp_stream* cur_stream = TAILQ_FIRST(&sender->control_list);
    j_tcp_stream* last = TAILQ_LAST(&sender->control_list,control_head);

    int cnt = 0;
    int ret = -1;
    j_tcp_stream* next = NULL;
    while(cur_stream){
        if(++cnt > thresh){
            break;
        }

        next = TAILQ_NEXT(cur_stream,snd->control_link);
        TAILQ_REMOVE(&sender->control_list,cur_stream,snd->control_link);

        sender->control_list_cnt--;
        if(cur_stream->snd->on_control_list){
            cur_stream->snd->on_control_list = 0;

            ret = j_tcp_send_controlpkt(cur_stream,cur_ts); //根据stream的状态来进行处理
            if(ret < 0){
                TAILQ_INSERT_TAIL(&sender->control_list,cur_stream,snd->control_link);
                cur_stream->snd->on_control_list = 1;
                sender->control_list_cnt++;
                break;
            }
        }else{
            j_trace_tcp("Stream %d: not on control_list.\n",cur_stream->id);
        }
        if(cur_stream == last){
            break;
        }

        cur_stream =  next;
    }
    return cnt;
}

int j_tcp_write_datalist(j_sender* sender,uint32_t cur_ts,int thresh){
    j_tcp_manager* tcp = j_get_tcp_manager();
    assert(tcp != NULL);

    j_tcp_stream* cur_stream = TAILQ_FIRST(&sender->send_list);
    j_tcp_stream* last = TAILQ_LAST(&sender->send_list,send_head);

    int cnt = 0;
    int ret = -1;
    j_tcp_stream* next = NULL;

    while(cur_stream){
        if(++cnt > thresh){
            break;
        }
        next = TAILQ_NEXT(cur_stream,snd->send_link);
        TAILQ_REMOVE(&sender->send_list,cur_stream,snd->send_link);

        j_trace_tcp("send_list:%d,state : %d\n",cur_stream->snd->on_send_list,cur_stream->state);
        if(cur_stream->snd->on_send_list){
            ret = 0;

            if(cur_stream->state == J_TCP_ESTABLISHED){
                if(cur_stream->snd->on_control_list){
                    ret = -1;
                }else{
                    ret = j_tcp_flush_sendbuffer(cur_stream,cur_ts);
                }
            }else if(cur_stream->state == J_TCP_CLOSE_WAIT || 
                        cur_stream->state == J_TCP_FIN_WAIT_1 ||
                        cur_stream->state == J_TCP_LAST_ACK){
                ret = j_tcp_flush_sendbuffer(cur_stream,cur_ts);
            }else{
                j_trace_tcp("Stream %d:on_send_list at state:%d\n",
                             cur_stream->id,cur_stream->state);
            }

            if(ret < 0){
                TAILQ_INSERT_TAIL(&sender->send_list,cur_stream,snd->send_link);
                break;
            }else{
                cur_stream->snd->on_send_list = 0;
                sender->send_list_cnt--;

                if(cur_stream->snd->ack_cnt > 0){
                    if(cur_stream->snd->ack_cnt > ret){
                        cur_stream->snd->ack_cnt -= ret; 
                    }else{
                        cur_stream->snd->ack_cnt = 0;
                    }
                }

                if(cur_stream->control_list_waiting){
                    if(!cur_stream->snd->on_ack_list){
                        cur_stream->control_list_waiting = 0;
                        j_tcp_addto_controllist(tcp,cur_stream);
                    }
                }
            }
        }else{
            j_trace_tcp("Stream %d:not on send list.\n",cur_stream->id);
        }
        if(cur_stream == last){
            break;
        }
        cur_stream = next;
    }
    return cnt;
}

int j_tcp_write_acklist(j_sender* sender,uint32_t cur_ts,int thresh){
    j_tcp_manager* tcp = j_get_tcp_manager();
    assert(tcp != NULL);

    j_tcp_stream* cur_stream = TAILQ_FIRST(&sender->ack_list);
    j_tcp_stream* last = TAILQ_LAST(&sender->ack_list,ack_head);
    j_tcp_stream* next  = NULL;

    int cnt = 0;
    int to_ack = 0;
    int ret = 0;

    while(cur_stream){
        if(++cnt > thresh){
            break;
        }

        next = TAILQ_NEXT(cur_stream,snd->ack_link);
        if(cur_stream->snd->on_ack_list){
            to_ack = 0;

            if(cur_stream->state == J_TCP_ESTABLISHED || 
                     cur_stream->state == J_TCP_CLOSE_WAIT ||
                     cur_stream->state == J_TCP_FIN_WAIT_1 ||
                     cur_stream->state == J_TCP_FIN_WAIT_2 ||
                     cur_stream->state == J_TCP_TIME_WAIT){
                if(cur_stream->rcv->recvbuf){
                    if(TCP_SEQ_LEQ(cur_stream->rcv_nxt,
                                cur_stream->rcv->recvbuf->head_seq + 
                                cur_stream->rcv->recvbuf->merged_len)){
                        //返回的报文的ack序列号是正确的
                        to_ack = 1;
                    }
                }
            }else{
                j_trace_tcp("Stream %u(%d):"
                             "Try sending ack at not proper state."
                             "seq:%u,ack_seq:%u,on_controol_list:%u\n",
                             cur_stream->id,cur_stream->state,
                             cur_stream->snd_nxt,cur_stream->rcv_nxt,
                             cur_stream->snd->on_control_list);
            }

            if(to_ack){
               while(cur_stream->snd->ack_cnt > 0){
                   ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK,NULL,0);
                   if(ret < 0){
                       break;
                   }
                   cur_stream->snd->ack_cnt--;
               }

               if(cur_stream->snd->is_wack){
                   cur_stream->snd->is_wack = 0;
                   ret = j_tcp_send_tcppkt(cur_stream,cur_ts,J_TCPHDR_ACK | 
                                            J_TCPHDR_CWR,NULL,0);
                   if(ret < 0){
                       cur_stream->snd->is_wack = 1;
                   }
               }

               if(!(cur_stream->snd->ack_cnt || cur_stream->snd->is_wack)){
                   cur_stream->snd->on_ack_list = 0;
                   TAILQ_REMOVE(&sender->ack_list,cur_stream,snd->ack_link);
                   sender->ack_list_cnt--;
               }
            }else{
                cur_stream->snd->on_ack_list = 0;
                cur_stream->snd->ack_cnt = 0;
                cur_stream->snd->is_wack = 0;
                TAILQ_REMOVE(&sender->ack_list,cur_stream,snd->ack_link);
                sender->ack_list_cnt--;
            }

            if(cur_stream->control_list_waiting){
                if(!cur_stream->snd->on_send_list){
                    cur_stream->control_list_waiting = 1;
                    j_tcp_addto_controllist(tcp,cur_stream);
                }
            }
        }else{
            j_trace_tcp("Stream %d:not on ack list.\n",cur_stream->id);
            TAILQ_REMOVE(&sender->ack_list,cur_stream,snd->ack_link);
            sender->ack_list_cnt--;
        }

        if(cur_stream == last){
            break;
        }
                          
        cur_stream = next;
    }
    return cnt;
}

//由于使用的是poll，并且注册了POLLOUT，所以该函数随时都被会调用到.它的作用就是对sender中的control list 、send list和ack list进行处理
void j_tcp_write_chunks(uint32_t cur_ts){
    j_tcp_manager* tcp = j_get_tcp_manager();
    assert(tcp != NULL);

    int thresh = J_MAX_CONCURRENCY;
    assert(tcp->g_sender != NULL);

    if(tcp->g_sender->control_list_cnt){
        j_tcp_write_controllist(tcp->g_sender,cur_ts,thresh);
    }
    if(tcp->g_sender->ack_list_cnt){
        j_tcp_write_acklist(tcp->g_sender,cur_ts,thresh);
    }

    if(tcp->g_sender->send_list_cnt){
        j_tcp_write_datalist(tcp->g_sender,cur_ts,thresh);
    }

#if J_ENABLE_MULTI_NIC
    int i = 0;
    for(;i < ETH_NUM;++i){
        if(tcp->n_sender[i]->control_list_cnt){
            j_tcp_write_controllist(tcp->n_sender[i],cur_ts,thresh);
        }
        if(tcp->n_sender[i]->ack_list_cnt){
            j_tcp_write_acklist(tcp->n_sender[i],cur_ts,thresh);
        }
        if(tcp->n_sender[i]->send_list_cnt){
            j_tcp_write_datalist(tcp->n_sender[i],cur_ts,thresh);
        }
    }
#endif

}
