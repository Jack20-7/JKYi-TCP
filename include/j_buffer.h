#ifndef _JKYI_TCP_BUFFER_H_
#define _JKYI_TCP_BUFFER_H_

#include"j_mempool.h"
#include"j_queue.h"
#include"j_tree.h"

#include<stdint.h>
#include<sys/types.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<assert.h>
#include<errno.h>

enum rb_caller{
    AT_ARP,
    AT_MTCP
};


#define MAX(a,b) ((a)>(b))?(a):(b)
#define MIN(a,b) ((a)<(b))?(a):(b)

//send buffer manager
typedef struct _j_sb_manager{
    size_t chunk_size;        //每一个chunk的大小
    uint32_t cur_num;         //当前取出的数量
    uint32_t cnum;            //chunk的数量,也就是内存池中的分配的chunk的数量
    struct _j_mempool* mp;    
    struct _j_sb_queue* freeq;
}j_sb_manager;

//发送缓冲区
typedef struct _j_send_buffer{
    unsigned char* data;//分配空间的起始地址
    unsigned char* head;//读指针

    uint32_t head_off;  //相当于是读偏移量
    uint32_t tail_off;  //相当于是写偏移量
    uint32_t len;       //当前已经使用了的空间的大小,也就是存储的数据长度
    uint64_t cum_len;
    uint32_t size;      //内存池分配的chunk空间的大小

    uint32_t head_seq;  //存储数据头部的序号
    uint32_t init_seq;  //初始序号
}j_send_buffer;

#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif


typedef struct _j_sb_queue{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;  //写偏移量

    j_send_buffer* volatile* _q;
}j_sb_queue;

#define NextIndex(sq,i)                 (i != sq->_capacity ? i + 1 : 0)
#define PrevIndex(sq,i)                 (i != 0 ? i - 1 : sq->_capacity)
#define MemoryBarrier(buf, idx) __asm__ volatile("" : : "m" (buf), "m" (idx))


typedef struct _j_rb_frag_queue{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;

    struct _j_fragment_ctx* volatile* _q; 
}j_rb_frag_queue;

typedef struct _j_fragment_ctx{
    uint32_t seq;
    uint32_t len:31,
             is_calloc:1;  //是自己分配的还是从内存池中拿取的
    struct _j_fragment_ctx* next;
}j_fragment_ctx;

typedef struct _j_ring_buffer{
    u_char* data;  //头指针
    u_char* head;  //读指针

    //读写偏移量
    uint32_t head_offset;
    uint32_t tail_offset;

    int merged_len;      
    uint64_t cum_len;
    int last_len;          //当前有效的数据长度
    int size;              //分配的chunk的长度

    //序号相关的信息
    uint32_t head_seq;
    uint32_t init_seq;

    j_fragment_ctx* fctx;
}j_ring_buffer;

typedef struct _j_rb_manager{
    size_t chunk_size;     //chunk的大小
    uint32_t cur_num;      //分配的ring_buffer的数量
    uint32_t cnum;         //chunk的数量

    j_mempool* mp;        //chunk的内存池
    j_mempool* frag_mp;   //fragment_ctx的内存池

    //两个fragment队列，分配时先尝试从第一个中进行分配，如果没有分配到再去第二个队列中申请
    j_rb_frag_queue* free_fragq;
    j_rb_frag_queue* free_fragq_int;
}j_rb_manager;



typedef struct _j_stream_queue{
    index_type _capacity;
    volatile index_type _head;
    volatile index_type _tail;

    struct _j_tcp_stream* volatile* _q;
}j_stream_queue;

typedef struct _j_stream_queue_int{
    struct _j_tcp_stream** array;
    int size;

    int first;
    int last;
    int count;
}j_stream_queue_int;

j_sb_manager* j_sbmanager_create(size_t chunk_size,uint32_t cnum);
j_rb_manager* RBManagerCreate(size_t chunk_size,uint32_t cnum);

j_stream_queue* CreateStreamQueue(int capacity);

j_stream_queue_int* CreateInternalStreamQueue(int size);
void DestroyInternalStreamQueue(j_stream_queue_int* sq);

j_send_buffer* SBInit(j_sb_manager* sbm,uint32_t init_seq);
void SBFree(j_sb_manager *sbm, j_send_buffer *buf);
size_t SBPut(j_sb_manager *sbm, j_send_buffer *buf, const void *data, size_t len);
int SBEnqueue(j_sb_queue *sq, j_send_buffer *buf);
size_t SBRemove(j_sb_manager *sbm, j_send_buffer *buf, size_t len);


size_t RBRemove(j_rb_manager *rbm, j_ring_buffer* buff, size_t len, int option);
int RBPut(j_rb_manager *rbm, j_ring_buffer* buff, 
           void* data, uint32_t len, uint32_t cur_seq);
void RBFree(j_rb_manager *rbm, j_ring_buffer* buff);

int StreamInternalEnqueue(j_stream_queue_int *sq, struct _j_tcp_stream *stream);
struct _j_tcp_stream *StreamInternalDequeue(j_stream_queue_int *sq);


/*** ******************************** sb queue ******************************** ***/


j_sb_queue *CreateSBQueue(int capacity);
int StreamQueueIsEmpty(j_stream_queue *sq);


j_send_buffer *SBDequeue(j_sb_queue *sq);

j_ring_buffer *RBInit(j_rb_manager *rbm, uint32_t init_seq);


struct _j_tcp_stream *StreamDequeue(j_stream_queue *sq);
int StreamEnqueue(j_stream_queue *sq, struct _j_tcp_stream *stream);

void DestroyStreamQueue(j_stream_queue *sq);


#endif
