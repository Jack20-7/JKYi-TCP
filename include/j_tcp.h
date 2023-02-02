#ifndef _JKYI_TCP_TCP_H_
#define _JKYI_TCP_TCP_H_

#include"j_timer.h"
#include"j_buffer.h"
#include"j_hash.h"
#include"j_config.h"
#include"j_epoll_inner.h"

#define ETH_NUM  4

//TCP连接的状态
typedef enum _j_tcp_state{
    J_TCP_CLOSED = 0,
    J_TCP_LISTEN = 1,
    J_TCP_SYN_SENT = 2,
    J_TCP_SYN_RCVD = 3,
    J_TCP_ESTABLISHED = 4,
    J_TCP_CLOSE_WAIT = 5,
    J_TCP_FIN_WAIT_1 = 6,
    J_TCP_CLOSING = 7,
    J_TCP_LAST_ACK = 8,
    J_TCP_FIN_WAIT_2 = 9,
    J_TCP_TIME_WAIT = 10,
}j_tcp_state;

#define J_TCPHDR_FIN 0x01
#define J_TCPHDR_SYN 0x02
#define J_TCPHDR_RST 0x04
#define J_TCPHDR_PSH 0x08
#define J_TCPHDR_ACK 0x10
#define J_TCPHDR_URG 0x20
#define J_TCPHDR_ECE 0x40
#define J_TCPHDR_CWR 0x80

//下面是TCP首部的options字段所能够携带的选项
//MSS           TCP报文所能够携带的最大数据字节数
//WSCALE        窗口扩大因子
//SACK_PERMID   表示发送方支持sack
//SACK          sack块的信息
//TIMESTAMP     时间戳
//NOP           选项填充位
#define J_TCPOPT_MSS_LEN                4
#define J_TCPOPT_WSCALE_LEN             3
#define J_TCPOPT_SACK_PERMIT_LEN        2
#define J_TCPOPT_SACK_LEN               10
#define J_TCPOPT_TIMESTAMP_LEN          10

#define TCP_DEFAULT_MSS                 1460
#define TCP_DEFAULT_WSCALE              7
#define TCP_INITIAL_WINDOW              14600
#define TCP_MAX_WINDOW                  65535

#define J_SEND_BUFFER_SIZE              8192
#define J_RECV_BUFFER_SIZE              8192
#define J_TCP_TIMEWAIT                  0
#define J_TCP_TIMEOUT                   30

#define TCP_MAX_RTX                       16
#define TCP_MAX_SYN_RETRY                 7
#define TCP_MAX_BACKOFF                   7

#define TCP_SEQ_LT(a,b)                 ((int32_t)((a) - (b)) < 0)
#define TCP_SEQ_LEQ(a,b)                ((int32_t)((a) - (b)) <= 0)
#define TCP_SEQ_GT(a,b)                 ((int32_t)((a) - (b)) > 0)
#define TCP_SEQ_GEQ(a,b)                ((int32_t)((a) - (b)) >= 0)
#define TCP_SEQ_BETWEEN(a,b,c)          (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))     

#define HZ                              1000
#define TIME_TICK                       (1000000 / HZ)
#define TIMEVAL_TO_TS(t)                (uint32_t)((t)->tv_sec * HZ + ((t)->tv_usec / TIME_TICK))

#define TS_TO_USEC(t)                   ((t) * TIME_TICK)
#define TS_TO_MSEC(t)                   (TS_TO_USEC(t) / 1000)
#define MSEC_TO_USEC(t)                 ((t) * 1000) 
#define USEC_TO_SEC(t)                  ((t) / 1000000)

#define TCP_INITIAL_RTO                 (MSEC_TO_USEC(500) / TIME_TICK)

#if J_ENABLE_BLOCKING

#define SBUF_LOCK_INIT(lock,errmsg,action);  \
         if(pthread_mutex_init(lock,PTHREAD_PROCESS_PRIVATE)){ \
             perror("pthread_mutex_init" errmsg); \
             action; \
         }
#define SBUF_LOCK_DESTROY(lock) pthread_mutex_destroy(lock)
#define SBUF_LOCK(lock)         pthread_mutex_lock(lock)
#define SBUF_UNLOCK(lock)       pthread_mutex_unlock(lock)

#else

#define SBUF_LOCK_INIT(lock,errmsg,action);        \
        if(pthread_spin_init(lock,PTHREAD_PROCESS_PRIVATE)){  \
            perror("pthread_spin_init" errmsg); \
            action;\
        }
#define SBUF_LOCK_DESTROY(lock)       pthread_spin_destroy(lock)
#define SBUF_LOCK(lock)               pthread_spin_lock(lock)
#define SBUF_UNLOCK(lock)             pthread_spin_unlock(lock)

#endif

enum tcp_option{
    TCP_OPT_END = 0,
    TCP_OPT_NOP = 1,
    TCP_OPT_MSS = 2,
    TCP_OPT_WSCALE = 3,
    TCP_OPT_SACK_PERMIT = 4,
    TCP_OPT_SACK = 5,
    TCP_OPT_TIMESTAMP = 8,
};

enum tcp_close_reason{
    TCP_NOT_CLOSED = 0,
    TCP_ACTIVE_CLOSE = 1,
    TCP_PASSIVE_CLOSE = 2,
    TCP_CONN_FAIL = 3,
    TCP_CONN_LOST = 4,
    TCP_RESET = 5,
    TCP_NO_MEM = 6,
    TCP_NOT_ACCEPTED = 7,
    TCP_TIMEOUT = 8,
};

enum ack_opt{
    ACK_OPT_NOW,
    ACK_OPT_AGGREGATE,
    ACK_OPT_WACK,
};

enum socket_type{
    J_TCP_SOCK_UNUSED,
    J_TCP_SOCK_STREAM,
    J_TCP_SOCK_PROXY,
    J_TCP_SOCK_LISTENER,
    J_TCP_SOCK_EPOLL,
    J_TCP_SOCK_PIPE,
};

typedef struct _j_tcp_timestamp{
    uint32_t ts_val; //发送方当前的时间戳
    uint32_t ts_ref; //上一次收到对方发送来的数据包的时间戳
}j_tcp_timestamp;

typedef struct _j_rtm_stat{
    uint32_t tdp_ack_cnt;
    uint32_t tdp_ack_bytes;
    uint32_t ack_upd_cnt;
    uint32_t ack_upd_bytes;
    uint32_t rto_cnt;
    uint32_t rto_bytes;
}j_rtm_stat;

typedef struct _j_tcp_recv{
    //接收窗口的大小
    uint32_t rcv_wnd;
    uint32_t irs;             //通信对端的初始序列号
    //下面两个两个成员在强制更新发送窗口时会用到
    uint32_t snd_wl1;         //记录上一次更新发送窗口的seq,也就是收到的最大seq
    uint32_t snd_wl2;         //记录上一次更新发送窗口的ack,也就是收到的最大ack

    uint32_t dup_acks;        //收到的重复ACK报文的数量
    uint32_t last_ack_seq;    //上一次接收的数据包的确认序列号

    uint32_t ts_recent;       //最近收到的数据包携带的时间戳(对方的时间戳)
    uint32_t ts_lastack_rcvd; //上一次发送的数据包的时间戳
    uint32_t ts_last_ts_upd;  
    uint32_t ts_tw_expire;   //该连接处于timewait时的过期时间

    //下面5个成员在估算rtt的时候会用到
    //RTO = srtt >> 3 + rttvar
    uint32_t srtt;            //平滑的rtt，估算rtt的时候需要用到,它是时机rtt的八倍
    uint32_t mdev;           //rtt的平均偏差,用来衡量RTT的抖动情况
    uint32_t mdev_max;       //上一个RTT内的最大mdev,代表上一个RTT内时延的波动情况
    uint32_t rttvar;         //mdev_max的平均值
    uint32_t rtt_seq;

    //接收缓存
    struct _j_ring_buffer* recvbuf;
    TAILQ_ENTRY(_j_tcp_stream) he_link;

#if J_ENABLE_BLOCKING
    TAILQ_ENTRY(_j_tcp_stream) rcv_br_link;
    pthread_cond_t read_cond;
    pthread_mutex_t read_lock;

    // TAILQ_ENTRY(_j_tcp_stream) snd_br_link;
    // pthread_mutex_t write_lock;
    // pthread_cond_t write_cond;
#else
    pthread_spinlock_t read_lock;
#endif
}j_tcp_recv;

typedef struct _j_tcp_send{
    uint16_t ip_id;
    uint16_t mss;
    uint16_t eff_mss;

    //窗口扩大因子主要是为了扩大window字段而引入的
    uint8_t wscale_mine;  //当前机器的窗口扩大因子
    uint8_t wscale_peer;  //对端机器的窗口扩大因子
    int8_t nif_out;

    unsigned char* d_haddr;
    uint32_t snd_una;   //未确认报文的最小序列号
    uint32_t snd_wnd;   //发送窗口的大小

    uint32_t peer_wnd;  //对方接收窗口的大小 
    uint32_t iss;       //初始序列号
    uint32_t fss;       //发送fin报文时，需要以它作为序列号

    uint8_t nrtx;      //重传的次数
    uint8_t max_nrtx;  //最大重传次数
    uint32_t rto;      //超时时间
    uint32_t ts_rto;   //cur_ts + rto

    uint32_t cwnd;     //拥塞窗口的大小
    uint32_t ssthresh; //阙值
    uint32_t ts_lastack_sent;  //上一层发送ack报文的 时间

    uint8_t is_wack:1,   //返回的ack报文tcp首部的CWR设置为1
            ack_cnt:6;  //需要返回的ack报文的数量

    uint8_t on_control_list;
    uint8_t on_send_list;
    uint8_t on_ack_list;
    uint8_t on_sendq;
    uint8_t on_ackq;
    uint8_t on_closeq;
    uint8_t on_resetq;

    uint8_t on_closeq_int:1,
            on_resetq_int:1,
            is_fin_sent:1,     //是否发送过fin报文
            is_fin_ackd:1;

    TAILQ_ENTRY(_j_tcp_stream) control_link;
    TAILQ_ENTRY(_j_tcp_stream) send_link;
    TAILQ_ENTRY(_j_tcp_stream) ack_link;
    TAILQ_ENTRY(_j_tcp_stream) timer_link;
    TAILQ_ENTRY(_j_tcp_stream) timeout_link;

    struct _j_send_buffer* sndbuf;

#if J_ENABLE_BLOCKING
    TAILQ_ENTRY(_j_tcp_stream) snd_br_link;
    pthread_mutex_t write_lock;
    pthread_cond_t write_cond;

#else
    pthread_spinlock_t write_lcok;
#endif
}j_tcp_send;

//TCP控制块
typedef struct _j_tcp_stream{
#if J_ENABLE_SOCKET_C10M
    struct _j_socket* s;
#endif

    struct _j_socket_map* socket;

    uint32_t id:24,
             stream_type:8;

    //IP地址信息
    uint32_t saddr;
    uint32_t daddr;

    //端口号信息
    uint16_t sport;
    uint16_t dport;

    uint8_t state;         //TCP连接的状态
    uint8_t close_reason;  //关闭的原因

    uint8_t on_hash_table;
    uint8_t on_timewait_list;

    uint8_t ht_idx;
    uint8_t closed;       //是否调用j_closed进行关闭
    uint8_t is_bound_addr;  //是否绑定了地址
    uint8_t need_wnd_adv;   //window == 0时，需要将它设置为1

    int16_t on_rto_idx;
    uint16_t on_timeout_list:1,
             on_rcv_br_list:1,
             on_snd_br_list:1,
             //是否有TIMESTAMP选项
             saw_timestamp:1,
             //是否允许使用sack
             sack_permit:1,
             control_list_waiting:1,//等待被放入到control list上面去
             have_reset:1; //是否收到了rst报文

    //上一次活跃的时间
    uint32_t last_active_ts;

    j_tcp_recv* rcv;
    j_tcp_send* snd;
    uint32_t snd_nxt;   //要发送的数据包的序列号
    uint32_t rcv_nxt;   //期待收到的数据包的序列号

    //解决j_close的bug
    pthread_cond_t closed_cond;
    pthread_mutex_t closed_mutex;
}j_tcp_stream;

typedef struct _j_sender{
    int ifidx;     //网卡的序号
    TAILQ_HEAD(control_head,_j_tcp_stream) control_list;
    TAILQ_HEAD(send_head,_j_tcp_stream) send_list;
    TAILQ_HEAD(ack_head,_j_tcp_stream) ack_list;

    int control_list_cnt;
    int send_list_cnt;
    int ack_list_cnt;
}j_sender;


typedef struct _j_thread_context{
    int cpu;
    pthread_t thread;
    uint8_t  done:1,
             exit:1,
             interrupt:1;

    struct _j_tcp_manager* tcp_manager;
    void* io_private_context;

    pthread_mutex_t smap_lock;
    pthread_mutex_t flow_pool_lock;
    pthread_mutex_t socket_pool_lock;
}j_thread_context;

typedef struct _j_tcp_manager{
    //内存池
    struct _j_mempool* flow; //存储的是j_tcp_stream
    struct _j_mempool* rcv;  //存放的是j_tcp_recv
    struct _j_mempool* snd;  //存放的是j_tcp_send
    struct _j_mempool* mv;

    struct _j_sb_manager* rbm_snd;
    struct _j_rb_manager* rbm_rcv;

    struct _j_hashtable* tcp_flow_table; //用于创建tcp_stream时快速对已有straem进行查找

#if J_ENABLE_SOCKET_C10M
    struct _j_socket_table* fdtable;
#endif

    uint32_t s_index;
    struct _j_socket_map* smap;
    TAILQ_HEAD(,_j_socket_map) free_smap;

    struct _j_addr_pool* ap; //地址池,可以用来对使用过的地址进行缓存
    uint32_t gid;           //设置创建的stream的id
    uint32_t flow_cnt;     //tcp_flow_table上存放的stream的个数

    j_thread_context* ctx;

#if J_ENABLE_EPOLL_RB
    void* ep;
#else
    struct _j_epoll* ep;
#endif

    uint32_t ts_last_event;        //上一次有事件发生的时间

    struct _j_hashtable* listeners;    //listener的哈希表.

    struct _j_stream_queue* connectq;
    struct _j_stream_queue* sendq;
    struct _j_stream_queue* ackq;

    struct _j_stream_queue* closeq;
    struct _j_stream_queue_int* closeq_int; //closeq中需要延迟处理的stream就存放在这里

    struct _j_stream_queue* resetq;
    struct _j_stream_queue_int* resetq_int; //resetq中需要延迟处理的stream就放在这里

    struct _j_stream_queue* destroyq;

    struct _j_sender* g_sender;
    //多网卡会用到
    struct _j_sender* n_sender[ETH_NUM];

    //RTO队列
    struct _j_rto_hashstore* rto_store;
    //timewait状态的连接所在的队列
    TAILQ_HEAD(timewait_head,_j_tcp_stream) timewait_list;
    //保活队列
    TAILQ_HEAD(timeout_head,_j_tcp_stream) timeout_list;

    int rto_list_cnt;
    int timewait_list_cnt;
    int timeout_list_cnt;

#if J_ENABLE_BLOCKING
    TAILQ_HEAD(rcv_br_head,_j_tcp_stream) rcv_br_list;
    TAILQ_HEAD(snd_br_head,_j_tcp_stream) snd_br_list;
    int rcv_br_list_cnt;
    int snd_br_list_cnt;
#endif

    uint32_t cur_ts;
    int wakeup_flag;
    int is_sleeping;
}j_tcp_manager;

typedef struct _j_tcp_listener{
    int sockid;

#if J_ENABLE_SOCKET_C10M
    struct _j_socket* s;
#endif

    struct _j_socket_map* socket;

    int backlog;
    struct _j_stream_queue* acceptq;

    pthread_mutex_t accept_lock;
    pthread_cond_t accept_cond;

    TAILQ_ENTRY(_j_tcp_listener) he_link;
}j_tcp_listener;

uint8_t* EthernetOutput(j_tcp_manager* tcp,uint16_t h_proto,
                         int nif,unsigned char* dst_haddr,uint16_t iplen);

uint8_t* IPOutput(j_tcp_manager* tcp,j_tcp_stream* stream,uint16_t tcplen);

j_tcp_stream* CreateTcpStream(j_tcp_manager* tcp,struct _j_socket_map* socket,int type,
                                 uint32_t saddr,uint16_t sport,uint32_t daddr,uint16_t dport);

uint8_t* IPOutputStandalone(j_tcp_manager* tcp,uint8_t protocol,uint16_t ip_id,uint32_t saddr,
                                uint32_t daddr,uint16_t payloadlen);

void j_tcp_addto_sendlist(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
void j_tcp_addto_controllist(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
void j_tcp_remove_controllist(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
void j_tcp_remove_sendlist(j_tcp_manager* tcp,j_tcp_stream* cur_stream);
void j_tcp_remove_acklist(j_tcp_manager* tcp,j_tcp_stream* cur_stream);

void j_tcp_write_chunks(uint32_t cur_ts);
int j_tcp_handle_apicall(uint32_t cur_ts);
int j_tcp_init_manager(j_thread_context* ctx);
void j_tcp_init_thread_context(j_thread_context* ctx);

void RaiseReadEvent(j_tcp_manager* tcp,j_tcp_stream* stream);
void RaiseWriteEvent(j_tcp_manager* tcp,j_tcp_stream* stream);
void RaiseCloseEvent(j_tcp_manager* tcp,j_tcp_stream* stream);
void RiaseErrorEvent(j_tcp_manager* tcp,j_tcp_stream* stream);

#endif
