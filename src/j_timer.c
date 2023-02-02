#include"j_timer.h"
#include"j_buffer.h"
#include"j_tcp.h"


extern void DestroyTcpStream(j_tcp_manager* tcp,j_tcp_stream* stream);

j_rto_hashstore* InitRTOHashstore(){
    j_rto_hashstore* hs = calloc(1,sizeof(j_rto_hashstore));
    if(!hs){
        return NULL;
    }

    int i = 0;
    for(;i < RTO_HASH + 1;i++){
        TAILQ_INIT(&hs->rto_list[i]);
    }

    return hs;
}

//重传队列
void AddtoRTOList(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    if(!tcp->rto_list_cnt){
        //如果当前链表上还没有tcp控制块的话
        tcp->rto_store->rto_now_idx = 0;
        tcp->rto_store->rto_now_ts = cur_stream->snd->ts_rto;
    }
    if(cur_stream->on_rto_idx < 0){
#if 0
        if(cur_stream->on_timeout_list){
            printf("Stream %u:cannot be in both "
                    "rto and timewait list\n",cur_stream->id);
            return ;
        }
#endif
        int32_t diff = (int32_t)(cur_stream->snd->ts_rto - tcp->rto_store->rto_now_ts);
        if(diff < RTO_HASH){
            int offset = cur_stream->snd->ts_rto % RTO_HASH;
            cur_stream->on_rto_idx = offset;
            TAILQ_INSERT_TAIL(&(tcp->rto_store->rto_list[offset]),
                             cur_stream,snd->timer_link);
        }else{
            cur_stream->on_rto_idx = RTO_HASH;
            TAILQ_INSERT_TAIL(&(tcp->rto_store->rto_list[RTO_HASH]),
                            cur_stream,snd->timer_link);
        }
        tcp->rto_list_cnt++;
    }
}

void RemoveFromRTOList(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    //如果不在上面
    if(cur_stream->on_rto_idx < 0){
        return ;
    }

    TAILQ_REMOVE(&(tcp->rto_store->rto_list[cur_stream->on_rto_idx]),
                 cur_stream,snd->timer_link);
    cur_stream->on_rto_idx = -1;
    tcp->rto_list_cnt--;
}


//timewait状态的队列
void AddtoTimewaitList(j_tcp_manager* tcp,j_tcp_stream* cur_stream,uint32_t cur_ts){
    cur_stream->rcv->ts_tw_expire = cur_ts + J_TCP_TIMEWAIT;
    if(cur_stream->on_timewait_list){
        //如果当前已经在timewait队列上的话
        TAILQ_REMOVE(&tcp->timewait_list,cur_stream,snd->timer_link);
        TAILQ_INSERT_TAIL(&tcp->timewait_list,cur_stream,snd->timer_link);
    }else{
        if(cur_stream->on_rto_idx >= 0){
            j_trace_timer("Stream %u: cannot be in both "
                           "timewait and rto list.\n",cur_stream->id);
            RemoveFromRTOList(tcp,cur_stream);
        }
        cur_stream->on_timewait_list = 1;
        TAILQ_INSERT_TAIL(&tcp->timewait_list,cur_stream,snd->timer_link);
        tcp->timewait_list_cnt++;
    }
}

void RemoveFromTimewaitList(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    if(!cur_stream->on_timewait_list){
        assert(0);
        return ;
    }

    TAILQ_INSERT_TAIL(&tcp->timewait_list,cur_stream,snd->timer_link);
    cur_stream->on_timewait_list = 0;
    tcp->timewait_list_cnt--;

}

//坚持队列
void AddtoTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    if(cur_stream->on_timeout_list){
        assert(0);
        return ;
    }

    cur_stream->on_timeout_list = 1;
    TAILQ_INSERT_TAIL(&tcp->timeout_list,cur_stream,snd->timeout_link);
    tcp->timeout_list_cnt++;
}

void RemoveFromTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    if(cur_stream->on_timeout_list){
        cur_stream->on_timeout_list = 0;
        TAILQ_REMOVE(&tcp->timeout_list,cur_stream,snd->timeout_link);
        tcp->timeout_list_cnt--;
    }
}

void UpdateTimeoutList(j_tcp_manager* tcp,j_tcp_stream* cur_stream){
    if(cur_stream->on_timeout_list){
        TAILQ_REMOVE(&tcp->timeout_list,cur_stream,snd->timeout_link);
        TAILQ_INSERT_TAIL(&tcp->timeout_list,cur_stream,snd->timeout_link);
    }
}

//更新重传计时器
void UpdateRetransmissionTimer(j_tcp_manager* tcp,j_tcp_stream* cur_stream,
                                                                 uint32_t cur_ts){
    assert(cur_stream->snd->rto > 0);
    cur_stream->snd->nrtx = 0;  //重传次数清零

    if(cur_stream->on_rto_idx >= 0){
        //如果在rto队列上的话
        RemoveFromRTOList(tcp,cur_stream);
    }

    if(TCP_SEQ_GT(cur_stream->snd_nxt,cur_stream->snd->snd_una)){
        //还有未确认的报文
        cur_stream->snd->ts_rto = cur_ts + cur_stream->snd->rto;
        AddtoRTOList(tcp,cur_stream);
    }else{
        j_trace_timer("All packets are acked,snd_una:%u ,snd_nxt:%u\n",
                       cur_stream->snd->snd_una,cur_stream->snd_nxt);
    }
}

//处理重传
int HandleRTO(j_tcp_manager* tcp,uint32_t cur_ts,j_tcp_stream* cur_stream){
   
   uint8_t backoff;//退避指针

   if(cur_stream->snd->nrtx < TCP_MAX_RTX){
       //重传次数 + 1
       cur_stream->snd->nrtx++;
   }else{
       //达到了最大重传次数
       if(cur_stream->state < J_TCP_ESTABLISHED){
           //处于建立连接状态的话
           cur_stream->state = J_TCP_CLOSED;
           cur_stream->close_reason = TCP_CONN_FAIL;
           DestroyTcpStream(tcp,cur_stream);
       }else{
           cur_stream->state = J_TCP_CLOSED;
           cur_stream->close_reason = TCP_CONN_LOST;
           if(cur_stream->socket){
           }else{
               DestroyTcpStream(tcp,cur_stream);
           }
       }
       return -1;
   }

   if(cur_stream->snd->nrtx > cur_stream->snd->max_nrtx){
       cur_stream->snd->max_nrtx = cur_stream->snd->nrtx;
   }

   if(cur_stream->state == J_TCP_ESTABLISHED){
       //更新RTO时间
       uint32_t rto_prev;
       backoff = MIN(cur_stream->snd->nrtx,TCP_MAX_BACKOFF);
       rto_prev = cur_stream->snd->rto;
       cur_stream->snd->rto = ((cur_stream->rcv->srtt >> 3) + cur_stream->rcv->rttvar) 
                                  << backoff;
       if(cur_stream->snd->rto <= 0){
           cur_stream->snd->rto = rto_prev;
       }
   }else if(cur_stream->state >= J_TCP_SYN_SENT){
       if(cur_stream->snd->nrtx < TCP_MAX_BACKOFF){
           cur_stream->snd->rto <<= 1;
       }
   }
   
   //更新阙值
   cur_stream->snd->ssthresh = MIN(cur_stream->snd->cwnd,cur_stream->snd->peer_wnd) / 2;
   if(cur_stream->snd->ssthresh < (2 * cur_stream->snd->mss)){
       cur_stream->snd->ssthresh = cur_stream->snd->mss * 2;
   }

   //慢启动算法,如发生丢包，重新从慢启动开始
   cur_stream->snd->cwnd = cur_stream->snd->mss;

   j_trace_timer("Stream %d: Timeout.cwnd: %u,ssthresh: %u\n",
                     cur_stream->id,cur_stream->snd->cwnd,cur_stream->snd->ssthresh);

   if(cur_stream->state == J_TCP_SYN_SENT){
       // SYN报文丢失了的话
       if(cur_stream->snd->nrtx > TCP_MAX_SYN_RETRY){
           //如果已经达到的SYN报文的最大重传次数
           cur_stream->state = J_TCP_CLOSED;
           cur_stream->close_reason = TCP_CONN_FAIL;
           j_trace_timer("Stream %d:SYN retries excedd max retries.\n",cur_stream->id);
           if(cur_stream->socket){
           }else{
               DestroyTcpStream(tcp,cur_stream);
           }
           return -1;
       }
       //如果未达到SYN报文的最大重传次数的话，就对丢失的SYN报文进行重传
       j_trace_timer("Stream %d Retransmit SYN. snd_nxt: %u,snd_una: %u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);

   }else if(cur_stream->state == J_TCP_SYN_RCVD){
       //SYN + ACK报文丢失
       j_trace_timer("Stream %d Retransmit SYN + ACK.snd_nxt:%u,snd_una:%u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);
   }else if(cur_stream->state == J_TCP_ESTABLISHED){
       //数据丢失了
       j_trace_timer("Stream %d Retransmit data.snd_nxt:%u,snd_una:%u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);
   }else if(cur_stream->state == J_TCP_CLOSE_WAIT){
       //半关闭状态数据丢了
       j_trace_timer("Stream %d Retransmit data.snd_nxt:%u,snd_una:%u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);
   }else if(cur_stream->state == J_TCP_LAST_ACK){
       //FIN报文丢了
       j_trace_timer("Stream %d Retransmit FIN.snd_nxt:%u,snd_una:%u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);
   }else if(cur_stream->state == J_TCP_FIN_WAIT_1){
       //FIN报文丢失了
        j_trace_timer("Stream %d Retransmit FIN.snd_nxt:%u,snd_una:%u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);
   }else if(cur_stream->state == J_TCP_CLOSING){
       //ACK报文丢失了
        j_trace_timer("Stream %d Retransmit ACK.snd_nxt:%u,snd_una:%u\n",
                        cur_stream->id,cur_stream->snd_nxt,cur_stream->snd->snd_una);
   }else{
       j_trace_timer("Stream %d:not implemented state! state: %d,rto:%u\n",
                       cur_stream->id,cur_stream->state,cur_stream->snd->rto);
       assert(0);
       return -1;
   }

   //下面就是对数据包进行重传
   cur_stream->snd_nxt = cur_stream->snd->snd_una;
   if(cur_stream->state == J_TCP_ESTABLISHED || 
                cur_stream->state == J_TCP_CLOSE_WAIT){
       //发送数据包
       j_tcp_addto_sendlist(tcp,cur_stream);
   }else if(cur_stream->state == J_TCP_FIN_WAIT_1
                || cur_stream->state == J_TCP_CLOSING
                || cur_stream->state == J_TCP_LAST_ACK){
       if(cur_stream->snd->fss == 0){
           j_trace_timer("Stream %u: fss not set.\n",cur_stream->id);
       }

       if(TCP_SEQ_LT(cur_stream->snd_nxt,cur_stream->snd->fss)){
           if(cur_stream->snd->on_control_list){
               j_tcp_remove_controllist(tcp,cur_stream);
           }
           cur_stream->control_list_waiting = 1;
           j_tcp_addto_sendlist(tcp,cur_stream);
       }else{
           j_tcp_addto_controllist(tcp,cur_stream);
       }
   }else{
       j_tcp_addto_controllist(tcp,cur_stream);
   }

   return 0;
}

//对rto_list[RTO_HASH]这一条链表上的定时器进行重新加载
static inline void RearrangeRTOStore(j_tcp_manager* tcp){
    j_tcp_stream* walk ,*next;
    struct rto_head* rto_list = &tcp->rto_store->rto_list[RTO_HASH];
    int cnt = 0;

    for(walk = TAILQ_FIRST(rto_list);
            walk != NULL;walk = next){
        next = TAILQ_NEXT(walk,snd->timer_link);
        int32_t diff = (int32_t)(tcp->rto_store->rto_now_ts - walk->snd->ts_rto);
        if(diff < RTO_HASH){
            int offset = (diff + tcp->rto_store->rto_now_idx) % RTO_HASH;
            TAILQ_REMOVE(&tcp->rto_store->rto_list[RTO_HASH],
                                   walk,snd->timer_link);
            walk->on_rto_idx = offset;
            TAILQ_INSERT_TAIL(&tcp->rto_store->rto_list[offset],
                                   walk,snd->timer_link);
        }
        cnt++;
    }
}

void CheckRtmTimeout(j_tcp_manager* tcp,uint32_t cur_ts,int thresh){
    j_tcp_stream* walk,*next;
    struct rto_head* rto_list;

    if(!tcp->rto_list_cnt){
        return ;
    }

    int cnt = 0;
    while(1){
        rto_list = &tcp->rto_store->rto_list[tcp->rto_store->rto_now_idx];
        if((int32_t)(cur_ts - tcp->rto_store->rto_now_ts) < 0){
            break;
        }

        for(walk = TAILQ_FIRST(rto_list);walk != NULL;walk = next){
            if(++cnt > thresh){
                break;
            }
            next = TAILQ_NEXT(walk,snd->timer_link);
            if(walk->on_rto_idx >= 0){
                TAILQ_REMOVE(rto_list,walk,snd->timer_link);
                tcp->rto_list_cnt--;

                walk->on_rto_idx = -1;
                HandleRTO(tcp,cur_ts,walk);
            }else{
                j_trace_timer("Stream %d: not on rto list.\n",walk->id);
            }
        }

        if(cnt < thresh){
            break;
        }else{
            //如果链表上的节点 >= thresh的话，就需要进行重整
            tcp->rto_store->rto_now_idx = (tcp->rto_store->rto_now_idx + 1) % RTO_HASH;
            tcp->rto_store->rto_now_ts++;
            if(!(tcp->rto_store->rto_now_idx % 1000)){
                RearrangeRTOStore(tcp);
            }
        }
    }
}


void CheckTimewaitExpire(j_tcp_manager* tcp,uint32_t cur_ts,int thresh){
    j_tcp_stream* walk,*next;
    int cnt = 0;

    for(walk = TAILQ_FIRST(&tcp->timewait_list);
                   walk != NULL;walk = next){
        if(++cnt > thresh){
            break;
        }

        next = TAILQ_NEXT(walk,snd->timer_link);

        if(walk->on_timewait_list){
            if((int32_t)(cur_ts - walk->rcv->ts_tw_expire) >= 0){
                if(!walk->snd->on_control_list){
                    TAILQ_REMOVE(&tcp->timewait_list,walk,snd->timer_link);
                    walk->on_timewait_list = 0;
                    tcp->timewait_list_cnt--;

                    walk->state = J_TCP_CLOSED;
                    walk->close_reason = TCP_ACTIVE_CLOSE;
                    j_trace_timer("Stream %d:TCP_ST_CLOSED\n",walk->id);
                    DestroyTcpStream(tcp,walk);
                }
            }else{
                break;
            }
        }else{
            j_trace_timer("Stream %d: not on timewait list.\n",walk->id);
        }
    }
}

void CheckConnectionTimeout(j_tcp_manager* tcp,uint32_t cur_ts,int thresh){
    j_tcp_stream* walk,*next;
    int cnt = 0;

    for(walk = TAILQ_FIRST(&tcp->timeout_list);
              walk != NULL;walk = next){
        if(++cnt > thresh){
            break;
        }

        next = TAILQ_NEXT(walk,snd->timeout_link);
        if((int32_t)(cur_ts - walk->last_active_ts) >= (J_TCP_TIMEOUT * 1000)){
            j_trace_timer("Stream %d time out!\n",walk->id);
            walk->on_timeout_list = 0;
            TAILQ_REMOVE(&tcp->timeout_list,walk,snd->timeout_link);
            tcp->timeout_list_cnt--;

            //按道理来讲，这里不应该直接close掉，而是应该启动保活机制.
            //但是该协议栈没有实现保活机制
            walk->state = J_TCP_CLOSED;
            walk->close_reason = TCP_TIMEOUT;
            if(walk->socket){
            }else{
                DestroyTcpStream(tcp,walk);
            }
        }else{
            break;
        }
    }
}





