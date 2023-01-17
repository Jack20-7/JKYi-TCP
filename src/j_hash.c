#include"j_hash.h"
#include"j_tcp.h"

unsigned int HashFlow(const void* f){
    j_tcp_stream* flow = (j_tcp_stream*)f;

    unsigned int hash = 0;
    int i = 0;
    char* key  = (char*)&flow->saddr;

    for(;i < 12;++i){
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash & (NUM_BINS_FLOWS - 1);
}

int EqualFlow(const void* f1,const void* f2){
    j_tcp_stream* flow1 = (j_tcp_stream*)f1;
    j_tcp_stream* flow2 = (j_tcp_stream*)f2;

    return (flow1->saddr == flow2->saddr &&
            flow1->sport == flow2->sport && 
            flow1->daddr == flow2->daddr &&
            flow1->dport == flow2->dport);
}

unsigned int HashListener(const void* l){
    j_tcp_listener* listener = (j_tcp_listener*)l;

    return listener->socket->s_addr.sin_port & (NUM_BINS_LISTENERS - 1);
}

int EqualListener(const void* l1,const void* l2){
    j_tcp_listener* listener1 = (j_tcp_listener*)l1;
    j_tcp_listener* listener2 = (j_tcp_listener*)l2;

    return (listener1->socket->s_addr.sin_port == listener2->socket->s_addr.sin_port);
}

#define IS_FLOW_TABLE(x)    (x == HashFlow)
#define IS_LISTEN_TABLE(x)  (x == HashListener)

j_hashtable* CreateHashtable(unsigned int (*hashfn)(const void*),
                              int (*eqfn)(const void*,const void*),
                              int bins){
    int i = 0;
    j_hashtable* ht = calloc(1,sizeof(j_hashtable));
    if(!ht){
        printf("calloc:CreateHashtable");
        return 0;
    }

    ht->hashfn = hashfn;
    ht->eqfn = eqfn;
    ht->bins = bins;

    if(IS_FLOW_TABLE(hashfn)){
        ht->ht_stream = calloc(bins,sizeof(hash_bucket_head));
        if(!ht->ht_stream){
            printf("calloc:CreateHashtable: bins!\n");
            free(ht);
            return 0;
        }
        for(;i < bins;++i){
            TAILQ_INIT(&ht->ht_stream[i]);
        }
    }else{
        ht->ht_listener = calloc(bins,sizeof(list_bucket_head));
        if(!ht->ht_listener){
            printf("calloc:CreateHashtable bins\n");
            free(ht);
            return 0;
        }
        for(;i < bins;++i){
            TAILQ_INIT(&ht->ht_listener[i]);
        }
    }

    return ht;
}

void DestroyHashtable(j_hashtable* ht){
    if(IS_FLOW_TABLE(ht->hashfn)){
        free(ht->ht_stream);
    }else{
        free(ht->ht_listener);
    }
    free(ht);
}

int StreamHTInsert(j_hashtable* ht,void* it){
    int idx = 0;
    j_tcp_stream* item = (j_tcp_stream*)it;
    assert(item);

    idx = ht->hashfn(item);
    assert(idx >= 0 && idx < NUM_BINS_FLOWS);

    TAILQ_INSERT_TAIL(&ht->ht_stream[idx],item,rcv->he_link);

    item->ht_idx = TCP_AR_CNT;
    ht->ht_count++;

    return 0;
}

void* StreamHTRemove(j_hashtable* ht,void* it){
    hash_bucket_head* head;
    j_tcp_stream* item = (j_tcp_stream*)it;
    int idx = item->ht_idx;

    head = &ht->ht_stream[idx];
    TAILQ_REMOVE(head,item,rcv->he_link);

    ht->ht_count--;
    return (item);
}

void* StreamHTSearch(j_hashtable* ht,const void* it){
    int idx = 0;
    j_tcp_stream* walk = NULL;
    hash_bucket_head* head = NULL;
    const j_tcp_stream* item = (const j_tcp_stream*)it;
    assert(item);

    idx = ht->hashfn(item);
    assert(idx >= 0 && idx < NUM_BINS_FLOWS);

    head = &ht->ht_stream[idx];
    TAILQ_FOREACH(walk,head,rcv->he_link){
        if(ht->eqfn(walk,item)){
            return walk;
        }
    }
    return NULL;
}

int ListenerHTInsert(j_hashtable* ht,void* it){
    int idx = 0;
    j_tcp_listener* item = (j_tcp_listener*)it;
    assert(item);
    assert(ht);

    idx = ht->hashfn(item);
    assert(idx >= 0 && idx < NUM_BINS_LISTENERS);

    TAILQ_INSERT_TAIL(&ht->ht_listener[idx],item,he_link);
    ht->ht_count++;
#if 0
    j_trace_hash("insert listener,port = %d\n",item->socket->s_addr.sin_port);
#endif

    return 0;
}

void* ListenerHTRemove(j_hashtable* ht,void* it){
   list_bucket_head* head = NULL;
   int idx = 0;
   j_tcp_listener* item = (j_tcp_listener*)it;
   assert(item);
   assert(ht);

   idx = ht->hashfn(item);
   head = &ht->ht_listener[idx];
   TAILQ_REMOVE(head,item,he_link);

   ht->ht_count--;

   return (item);
}



void* ListenerHTSearch(j_hashtable* ht,const void* it){
    int idx = 0;
    j_tcp_listener item;
    uint16_t port = *((uint16_t*)it);
#if 0
    j_trace_hash("ListenerHTSearch port = %d\n",port);
#endif

    j_tcp_listener* walk = NULL;
    list_bucket_head* head  = NULL;

    struct _j_socket_map socket;

    socket.s_addr.sin_port = port;
    item.socket = &socket;

    idx = ht->hashfn(&item);
    head = &ht->ht_listener[idx];
    TAILQ_FOREACH(walk,head,he_link){
        if(ht->eqfn(&item,walk)){
            return walk;
        }
    }
    return NULL;
}



