#ifndef _JKYI_TCP_MEMPOOL_H_
#define _JKYI_TCP_MEMPOOL_H_

#include<stddef.h>

typedef unsigned char u_char;
//内存池的设计
enum{
    MEM_NORMAL,
    MEM_HUGEPAGE,
};

typedef struct _j_mem_chunk{
    int mc_free_chunks;        //记录了当前内存池中空闲chunk的数目
    struct _j_mem_chunk* next;
}j_mem_chunk;

typedef struct _j_mempool{
    u_char* mp_startptr;       //始终执行分配的那一块内存的起始地址
    j_mem_chunk* mp_freeptr;  //第一个空闲的j_mem_chunk

    int mp_free_chunks;       //空闲的chunk数
    int mp_total_chunks;      //一共的chunk数
    int mp_chunk_size;        //每一个chunk的大小
    int mp_type;              //是否使用了大页内存模式
}j_mempool;

j_mempool* j_mempool_create(int chunk_size,size_t total_size,int is_hugepage);
void j_mempool_destroy(j_mempool* mp);
void* j_mempool_alloc(j_mempool* mp);
void j_mempool_free(j_mempool* mp,void* p);


#endif
