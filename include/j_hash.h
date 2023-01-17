#ifndef _JKYI_TCP_HASH_H_
#define _JKYI_TCP_HASH_H_

#include<stdint.h>

#include"j_queue.h"

#define NUM_BINS_FLOWS               131072
#define NUM_BINS_LISTENERS           1024
#define TCP_AR_CNT                   3

#define HASH_BUCKET_ENTRY(type)\
    struct {                      \
        struct type*  tqh_first;   \
        struct type** tqh_last;    \
    }

typedef HASH_BUCKET_ENTRY(_j_tcp_stream)   hash_bucket_head;
typedef HASH_BUCKET_ENTRY(_j_tcp_listener) list_bucket_head;

typedef struct _j_hashtable{
    uint8_t ht_count;           //哈希表中节点的个数
    uint32_t bins;              //buckets数组的长度

    union{
        hash_bucket_head* ht_stream;
        list_bucket_head* ht_listener;
    };

    unsigned int (*hashfn)(const void*);      //哈希函数
    int (*eqfn)(const void* ,const void*);   //存储节点的比较函数
}j_hashtable;

void* ListenerHTSearch(j_hashtable* ht,const void* it);
void* StreamHTSearch(j_hashtable* ht,const void* it);
int ListenerHTInsert(j_hashtable* ht,void* it);
int StreamHTInsert(j_hashtable* ht,void* it);
void* StreamHTRemove(j_hashtable* ht,void* it);

unsigned int HashFlow(const void* f);
int EqualFlow(const void* f1,const void* f2);
unsigned int HashListener(const void* l);
int EqualListener(const void* l1,const void* l2);

j_hashtable* CreateHashtable(unsigned int (*hashfn)(const void*), //HashFn
                              int (*eqfn)(const void* ,const void*), //EqualFn
                              int bins);
void DestroyHashTable(j_hashtable* ht);

#endif
