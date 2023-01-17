#include"j_mempool.h"
#include"j_config.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<assert.h>
#include<unistd.h>
#include<sys/mman.h>

#include<hugetlbfs.h>

j_mempool* j_mempool_create(int chunk_size,size_t total_size,int is_hugepage){
   if(chunk_size < (int)sizeof(j_mem_chunk)){
       return NULL;
   }
   if(chunk_size % 4 != 0){
       printf("j_mempool_create-->chunk_size:%d\n",chunk_size);
       return NULL;
   }

   j_mempool* mp = calloc(1,sizeof(j_mempool));
   if(NULL == mp){
       printf("j_mempool_create-->calloc failed\n");
       return NULL;
   }

   mp->mp_type = is_hugepage;
   mp->mp_chunk_size = chunk_size;
   //为什么还要单独加上一个(chunk_size - 1)
   mp->mp_free_chunks = (total_size + (chunk_size - 1)) / chunk_size;
   mp->mp_total_chunks = mp->mp_free_chunks;

   if(is_hugepage == MEM_HUGEPAGE){
       //如果是大页内存模式
       mp->mp_startptr = get_huge_pages(total_size,GHP_DEFAULT);
       if(!mp->mp_startptr){
           free(mp);
           assert(0);
       }
   }else{
       //分配total_size大小的内存空间,内存空间以页为单位进行对齐
       int res = posix_memalign((void**)&mp->mp_startptr,getpagesize(),total_size);
       if(0 != res){
           free(mp);
           assert(0);
       }
   }

   if(geteuid() == 0){
       //如果是root用户的话，就将分配的那一块内存全部所在物理内存中，避免被swap出去
       if(mlock(mp->mp_startptr,total_size) < 0){
       }
   }

   mp->mp_freeptr = (j_mem_chunk*)mp->mp_startptr;
   mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
   mp->mp_freeptr->next = NULL;

   return mp;
}


void j_mempool_destroy(j_mempool* mp){
    if(mp->mp_type == MEM_HUGEPAGE){
        free_huge_pages(mp->mp_startptr);
    }else{
        free(mp->mp_startptr);
    }
    free(mp);
}

void* j_mempool_alloc(j_mempool* mp){
    j_mem_chunk* p = mp->mp_freeptr;
    if(mp->mp_free_chunks == 0){
        j_trace_mempool("has not free space to alloc\n");
        return NULL;
    }
    assert(p->mc_free_chunks > 0);

    p->mc_free_chunks--;
    mp->mp_free_chunks--;

    if(p->mc_free_chunks){
        mp->mp_freeptr= (j_mem_chunk*)((u_char*)p + mp->mp_chunk_size);
        mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
        mp->mp_freeptr->next = p->next;
    }else{
        mp->mp_freeptr= p->next;
    }
    return p;
}

void j_mempool_free(j_mempool* mp,void* p){
    j_mem_chunk* mcp = (j_mem_chunk*)p;

    //需要是对齐的
    assert(((u_char*)p - mp->mp_startptr) % mp->mp_chunk_size == 0);

    mcp->mc_free_chunks = 1;
    //头插的方式放回队列中
    mcp->next = mp->mp_freeptr;
    mp->mp_freeptr = mcp;
    mp->mp_free_chunks++;
}

int j_mempool_getfree_chunks(j_mempool* mp){
    return mp->mp_free_chunks;
}

uint32_t j_mempool_isdanger(j_mempool* mp){
#define DANGER_THREADSHOLD 0.95
#define SAFE_THREADSHOLD   0.90

   uint32_t danger_num = mp->mp_total_chunks * DANGER_THREADSHOLD;
   uint32_t safe_num = mp->mp_total_chunks * SAFE_THREADSHOLD;

   if((int)danger_num < (mp->mp_total_chunks - mp->mp_free_chunks)){
       return mp->mp_total_chunks - mp->mp_free_chunks - safe_num;
   }
   return 0;
}

