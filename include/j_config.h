#ifndef _JKYI_TCP_CONFIG_H_
#define _JKYI_TCP_CONFIG_H_

#define J_SELF_IP "192.168.200.130"
#define J_SELF_IP_HEX  0x82C8A8C0
#define J_SELF_MAC "00:0c:29:1a:5d:95"

#define J_MAX_CONCURRENCY        1024           //最大并发连接数
#define J_SNDBUF_SIZE            8192           //snd->snfbuf的大小
#define J_RCVBUF_SIZE            8192           //rcv->rcvbuf的大小
#define J_MAX_NUM_BUFFERS        1024
#define J_BACKLOG_SIZE           1024

#define J_ENABLE_MULTI_NIC       0
#define J_ENABLE_BLOCKING        1

#define J_ENABLE_EPOLL_RB        1
#define J_ENABLE_SOCKET_C10M     1
#define J_ENABLE_POSIX_API       1

#define J_SOCKFD_NR              (1024 * 1024)
#define J_BITS_PER_BYTE          8
#define J_DEBUG                  1


#ifdef J_DEBUG
//如果是在debug模式下，所有的日志都直接打到屏幕上

#define j_dbg(format, ...)            fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_api(format, ...)      fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_tcp(format, ...)      fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_buffer(format, ...)   fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_eth(format, ...)      fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_ip(format, ...)       fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_timer(format, ...)    fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_epoll(format, ...)    fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_socket(format, ...)   fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_hash(format, ...)     fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_stream(format, ...)   fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_mempool(format, ...)  fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define j_trace_nic(format, ...)      fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)


#else

#define j_dbg(format, ...) 
#define j_trace_api(format, ...)
#define j_trace_tcp(format, ...) 
#define j_trace_buffer(format, ...)
#define j_trace_eth(format, ...)
#define j_trace_ip(format, ...)
#define j_trace_timer(format, ...)
#define j_trace_epoll(format, ...)
#define j_trace_socket(format, ...)

#endif

#define UNUSED(expr)    do {(void)(expr); } while(0)

#endif
