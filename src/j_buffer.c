#include"j_buffer.h"

j_sb_manager* j_sbmanager_create(size_t chunk_size,uint32_t cnum){
    j_sb_manager* sbm = (j_sb_manager*)calloc(1,sizeof(j_sb_manager));
    if(!sbm){
        printf("SBManagerCreate() failed.%s\n",strerror(errno));
        return NULL;
    }
    sbm->chunk_size = chunk_size;
    sbm->cnum = cnum;
    sbm->mp = (struct _j_mempool*)j_mempool_create(chunk_size,(uint64_t)chunk_size * cnum,0);
    if(!sbm->mp){
        printf("Failed to create mem pool for sb.\n");
        free(sbm);
        return NULL;
    }
    sbm->freeq = CreateSBQueue(cnum);
    if(!sbm->freeq){
        printf("Failed to create free buffer queue.\n");
        j_mempool_destroy(sbm->mp);
        free(sbm);
        return NULL;
    }
    return sbm;
}

j_send_buffer* SBInit(j_sb_manager* sbm,uint32_t init_seq){
    j_send_buffer* buf;

    //首先尝试从空闲的sb队列中取出一个send buffer
    buf = SBDequeue(sbm->freeq);
    if(!buf){
        buf = (j_send_buffer*)malloc(sizeof(j_send_buffer));
        if(!buf){
            perror("malloc error for send buffer");
            return NULL;
        }
        buf->data = j_mempool_alloc(sbm->mp);
        if(!buf->data){
            printf("Failed to fetch memory chunk for data.\n");
            free(buf);
            return NULL;
        }
        sbm->cur_num++;
    }
    buf->head = buf->data;

    buf->head_off = buf->tail_off = 0;
    buf->len = buf->cum_len = 0;
    buf->size = sbm->chunk_size;

    buf->init_seq = buf->head_seq = init_seq;

    return buf;
}

void SBFree(j_sb_manager* sbm,j_send_buffer* buf){
    if(!buf){
        return ;
    }
    SBEnqueue(sbm->freeq,buf);
}

size_t SBPut(j_sb_manager* sbm,j_send_buffer* buf,const void* data,size_t len){
    size_t to_put = 0;
    if(len <= 0){
        return 0;
    }
    to_put = MIN(len,buf->size - buf->len);
    if(to_put <= 0){
        //当前已经没有空间还能够存储数据
        return -2;
    }

    if(buf->tail_off + to_put < buf->size){
        //如果能够放下要存储的数据
        memcpy(buf->data + buf->tail_off,data,to_put);
        buf->tail_off += to_put;
    }else{
        //如果放不下
        memmove(buf->data,buf->head,buf->len);
        buf->head = buf->data;
        buf->head_off = 0;
        memcpy(buf->head + buf->len,data,to_put);
        buf->tail_off = buf->len + to_put;
    }

    buf->len += to_put;
    buf->cum_len += to_put;

    return to_put;
}

size_t SBRemove(j_sb_manager* sbm,j_send_buffer* buf,size_t len){
    size_t to_remove;
    if(len <= 0){
        return 0;
    }
    to_remove = MIN(len,buf->len);
    if(to_remove <= 0){
        return -2;
    }

    buf->head_off += to_remove;
    buf->head = buf->data + buf->head_off;
    buf->head_seq += to_remove;
    buf->len -= to_remove;

    if(buf->len == 0 && buf->head_off > 0){
        //如果没有数据了
        buf->head = buf->data;
        buf->head_off = buf->tail_off = 0;
    }
    return to_remove;
}

//分配一个send buffer的队列
j_sb_queue* CreateSBQueue(int capacity){
    j_sb_queue* sq;

    sq = (j_sb_queue*)calloc(1,sizeof(j_sb_queue));
    if(!sq){
        return NULL;
    }

    sq->_q = (j_send_buffer**)calloc(capacity + 1,sizeof(j_send_buffer*));
    if(!sq->_q){
        free(sq);
        return NULL;
    }

    sq->_capacity = capacity;
    sq->_head = sq->_tail = 0;

    return sq;
}

void DestroySBQueue(j_sb_queue* sq){
    if(!sq){
        return ;
    }
    if(sq->_q){
        free((void*)sq->_q);
        sq->_q = NULL;
    }
    free(sq);
}

int SBEnqueue(j_sb_queue* sq,j_send_buffer* buf){
    index_type h = sq->_head;
    index_type t = sq->_tail;
    index_type nt = NextIndex(sq,t);

    if(nt != h){
        sq->_q[t] = buf;
        MemoryBarrier(sq->_q[t],sq->_tail);
        sq->_tail = nt;
        return 0;
    }

    printf("Exceed capacity of buf queue.\n");
    return -1;
}

j_send_buffer* SBDequeue(j_sb_queue* sq){
    index_type h = sq->_head;
    index_type t = sq->_tail;

    if(h != t){
        //如果还有send buffer
        j_send_buffer* buf = sq->_q[h];
        MemoryBarrier(sq->_q[h],sq->_head);
        sq->_head = NextIndex(sq,h);

        assert(buf);
        return buf;
    }

    return NULL;
}

j_rb_frag_queue* CreateRBFragQueue(int capacity){
    j_rb_frag_queue* rb_fragq;

    rb_fragq = (j_rb_frag_queue*)calloc(1,sizeof(j_rb_frag_queue));
    if(!rb_fragq){
        return NULL;
    }
    rb_fragq->_q = (j_fragment_ctx**)calloc(capacity + 1,sizeof(j_fragment_ctx*));
    if(!rb_fragq->_q){
        free(rb_fragq);
        return NULL;
    }

    rb_fragq->_capacity = capacity;
    rb_fragq->_head = rb_fragq->_tail = 0;

    return rb_fragq;
}

void DestroyRBFragQueue(j_rb_frag_queue* rb_fragq){
    if(!rb_fragq){
        return ;
    }
    if(rb_fragq->_q){
        free((void*)rb_fragq->_q);
        rb_fragq->_q = NULL;
    }

    free(rb_fragq);
}

int RBFragEnqueue(j_rb_frag_queue* rb_fragq,j_fragment_ctx* frag){
    index_type h = rb_fragq->_head;
    index_type t = rb_fragq->_tail;
    index_type nt = NextIndex(rb_fragq,t);

    //由于环形队列的特性，为了能够区分队列已满和队列为空这两种情况，这里会在
    //head和tail之间留一个空位
    if(nt != h){
        rb_fragq->_q[t] = frag;
        MemoryBarrier(rb_fragq->_q[t],rb_fragq->_tail);
        rb_fragq->_tail = nt;
        return 0;
    }
    printf("Exceed capacity of frag queue.\n");
    return -1;
}
struct _j_fragment_ctx* RBFragDequeue(j_rb_frag_queue* rb_fragq){
    index_type h = rb_fragq->_head;
    index_type t = rb_fragq->_tail;

    if(h != t){
        struct _j_fragment_ctx* frag = rb_fragq->_q[h];
        MemoryBarrier(rb_fragq->_q[h],rb_fragq->_head);
        rb_fragq->_head = NextIndex(rb_fragq,h);
        assert(frag);

        return frag;
    }
    return NULL;
}

//对ring_buffer的信息进行打印
void RBPrintInfo(j_ring_buffer* buff){
    printf("buff_data %p ,buff_size %d,buff_mlen %d,"
             "buff_clen %lu,buff_head %p (%d),buff_tail (%d)\n",
             buff->data,buff->size,buff->merged_len,buff->cum_len,
             buff->head,buff->head_offset,buff->tail_offset);
}

void RBPrintStr(j_ring_buffer* buff){
    RBPrintInfo(buff);
    printf("%s\n",buff->head);
}

void RBPrintHex(j_ring_buffer* buff){
    int i = 0;
    RBPrintInfo(buff);

    for(;i < buff->merged_len;++i){
        if(i != 0 && i % 16 == 0){
            printf("\n");
        }
        printf("%0x ",*((unsigned char*)buff->head + i));
    }
    printf("\n");
}

j_rb_manager* RBManagerCreate(size_t chunk_size,uint32_t cnum){
    j_rb_manager* rbm = (j_rb_manager*)calloc(1,sizeof(j_rb_manager));
    if(!rbm){
        perror("rbm_create calloc");
        return NULL;
    }

    rbm->chunk_size = chunk_size;
    rbm->cnum = cnum;
    rbm->mp = (j_mempool*)j_mempool_create(chunk_size,(uint64_t)chunk_size * cnum,0);
    if(!rbm->mp){
        printf("Failed to allocate rb mempool\n");
        free(rbm);
        return NULL;
    }
    rbm->frag_mp = (j_mempool*)j_mempool_create(sizeof(j_fragment_ctx),
                                                       cnum *sizeof(j_fragment_ctx),0);
    if(!rbm->frag_mp){
        printf("Failed to allocate frag_mp pool.\n");
        j_mempool_destroy(rbm->mp);
        free(rbm);
        return NULL;
    }

    rbm->free_fragq = CreateRBFragQueue(cnum);
    if(!rbm->free_fragq){
        printf("Failed to create free fragment queue.\n");
        j_mempool_destroy(rbm->mp);
        j_mempool_destroy(rbm->frag_mp);
        free(rbm);
        return NULL;
    }

    rbm->free_fragq_int = CreateRBFragQueue(cnum);
    if(!rbm->free_fragq_int){
        printf("Failed to create internal free fragment queue.\n");
        j_mempool_destroy(rbm->mp);
        j_mempool_destroy(rbm->frag_mp);
        DestroyRBFragQueue(rbm->free_fragq);
        free(rbm);
        return NULL;
    }
    return rbm;
}

//释放单个fragment
static inline void FreeFragmentContextSingle(j_rb_manager* rbm,j_fragment_ctx* frag){
    if(frag->is_calloc){
        free(frag);
    }else{
        j_mempool_free(rbm->frag_mp,frag);
    }
}

//释放所有的fragment
void FreeFragmentContext(j_rb_manager* rbm,j_fragment_ctx* fctx){
    j_fragment_ctx* remove;

    //assert(fctx);
    if(fctx == NULL){
        return ;
    }

    while(fctx){
        remove = fctx;
        fctx = fctx->next;
        FreeFragmentContextSingle(rbm,remove);
    }
}

static j_fragment_ctx* AllocateFragmentContext(j_rb_manager* rbm){
    j_fragment_ctx* frag;
    //首先尝试从队列中拿取
    frag = RBFragDequeue(rbm->free_fragq);
    if(!frag){
        frag = RBFragDequeue(rbm->free_fragq_int);  //再尝试去内部队列中去拿去
        if(!frag){
            //如果两个队列中都没有拿取到,就需要去内存池中拿取
            frag = j_mempool_alloc(rbm->frag_mp);
            if(!frag){
                //内存池中也没有了的话，就自己从堆区申请
                printf("fragments depleted,fall back to calloc.\n");
                frag = calloc(1,sizeof(j_fragment_ctx));
                if(frag == NULL){
                    printf("calloc failed.\n");
                    exit(-1);
                }
                frag->is_calloc = 1;
            }
        }
    }
    memset(frag,0,sizeof(*frag));
    return frag;
}

j_ring_buffer* RBInit(j_rb_manager* rbm,uint32_t init_seq){
    j_ring_buffer* buff = (j_ring_buffer*)calloc(1,sizeof(j_ring_buffer));

    if(buff == NULL){
        perror("rb_init buff");
        return NULL;
    }

    buff->data = j_mempool_alloc(rbm->mp);
    if(!buff->data){
        perror("rb_init MPAllocateChunk");
        free(buff);
        return NULL;
    }
    buff->size = rbm->chunk_size;
    buff->head = buff->data;
    buff->head_seq = init_seq;
    buff->init_seq = init_seq;

    rbm->cur_num++;

    return buff;
}

void RBFree(j_rb_manager* rbm,j_ring_buffer* buff){
    assert(buff);

    if(buff->fctx){
        FreeFragmentContext(rbm,buff->fctx);
        buff->fctx = NULL;
    }
    if(buff->data){
        j_mempool_free(rbm->mp,buff->data);
    }
    rbm->cur_num--;

    free(buff);
}

#define MAXSEQ               ((uint32_t)(0xFFFFFFFF))
/*----------------------------------------------------------------------------*/
static inline uint32_t GetMinSeq(uint32_t a, uint32_t b){
    if (a == b) return a;
    if (a < b) 
        return ((b - a) <= MAXSEQ/2) ? a : b;
    /* b < a */
    return ((a - b) <= MAXSEQ/2) ? b : a;
}
static inline uint32_t GetMaxSeq(uint32_t a, uint32_t b){
    if (a == b) return a;
    if (a < b) 
        return ((b - a) <= MAXSEQ/2) ? b : a;
    /* b < a */
    return ((a - b) <= MAXSEQ/2) ? a : b;
}

//判断两个fragment能够进行合并

// a_seq ---------------------------- a_end
// b_seq ---------------------------- b_end
static inline int CanMerge(const j_fragment_ctx* a,const j_fragment_ctx* b){
    uint32_t a_end = a->seq + a->len + 1;
    uint32_t b_end = b->seq + b->len + 1;
    //必须要是相交的才能够merge
    //也就是需要满足的条件是 a_end > b->seq && b->end > a->seq
    if(GetMinSeq(a_end,b->seq) == a_end
             || GetMinSeq(b_end,a->seq) == b_end){
        return 0;
    }
    return 1;
}

//merge a into b
static inline void MergeFragments(j_fragment_ctx* a,j_fragment_ctx* b){
    uint32_t min_seq,max_seq;
    min_seq = GetMinSeq(a->seq,b->seq);
    max_seq = GetMaxSeq(a->seq + a->len,b->seq + b->len);
    b->seq = min_seq;
    b->len = max_seq - min_seq;
}

int RBPut(j_rb_manager* rbm,j_ring_buffer* buff,void* data,uint32_t len,
                                                            uint32_t cur_seq){
    int putx,end_off;
    j_fragment_ctx* new_ctx;
    j_fragment_ctx* iter;
    j_fragment_ctx* prev,*pprev;
    int merged = 0;

    if(len <= 0){
        return 0;
    }
    if(GetMinSeq(buff->head_seq,cur_seq) != buff->head_seq){
        //如果要插入的数据的序列号 < 当前存储的元素的数据序列号
        return 0;
    }

    putx = cur_seq - buff->head_seq;
    end_off = putx + len;
    if(buff->size < end_off){
        return -2;
    }

    if((uint32_t)buff->size <= (buff->head_offset + (uint32_t)end_off)){
        //data的空间是足够的，但是由于前面存在空的空间，所以需要先位移
        memmove(buff->data,buff->head,buff->last_len);
        buff->tail_offset -= buff->head_offset;
        buff->head_offset = 0;
        buff->head = buff->data;
    }
    //将数据根据seq拷贝到指定的位置
    memcpy(buff->head + putx,data,len);

    //更新写偏移量
    if(buff->tail_offset < buff->head_offset + end_off){
        buff->tail_offset = buff->head_offset + end_off;
    }
    buff->last_len = buff->tail_offset - buff->head_offset;

    new_ctx = AllocateFragmentContext(rbm);
    if(!new_ctx){
        perror("allocating new_ctx failed");
        return 0;
    }
    new_ctx->seq = cur_seq;
    new_ctx->len = len;
    new_ctx->next = NULL;

    for(iter = buff->fctx,prev = NULL,pprev = NULL
             ;iter != NULL;
             pprev = prev,prev = iter,iter = iter->next){
        //寻找当前buffer的数据中是否能够有和插入数据合并的fragment
        if(CanMerge(new_ctx,iter)){
            MergeFragments(new_ctx,iter);

            //然后将第一个fragment删除
            if(prev == new_ctx){
                if(pprev){
                    pprev->next = iter;
                }else{
                    //表示要删除的是第一块fragment
                    buff->fctx = iter;
                }
            }
            FreeFragmentContextSingle(rbm,new_ctx);
            new_ctx = iter;
            merged = 1;    
        }else if(merged || GetMaxSeq(cur_seq + len,iter->seq) == iter->seq){
            //停止merge
            break;
        }
    }
    if(!merged){
        //如果没有能够merge上去的话，那么这里就需要把新数据对他的fragment给挂上去
        if(buff->fctx == NULL){
            buff->fctx = new_ctx;
        }else if(GetMinSeq(cur_seq,buff->fctx->seq) == cur_seq){
            //如果当前数据的起始序列号是最小的话
            new_ctx->next = buff->fctx;
            buff->fctx->next = new_ctx;
        }else{
            //表示数据的frament位置在中间或者在末尾的话
            prev->next  = new_ctx;
            new_ctx->next = iter;
        }
    }
    if(buff->head_seq == buff->fctx->seq){
        buff->cum_len += buff->fctx->len - buff->merged_len;
        buff->merged_len = buff->fctx->len;
    }
    return len;
}

size_t RBRemove(j_rb_manager* rbm,j_ring_buffer* buff,size_t len,int option){
    if(buff->merged_len < (int)len){
        len = buff->merged_len;
    }
    if(len == 0){
        return 0;
    }
#if 0
    buff->head_offset += len;
#else
    buff->head_offset = len;
#endif

    buff->head = buff->data + buff->head_offset;
    buff->head_seq += len;

    buff->merged_len -= len;
    buff->last_len -= len;

    if(len == buff->fctx->len){
        j_fragment_ctx* remove = buff->fctx;
        buff->fctx = buff->fctx->next;
        if(option == AT_ARP){
            RBFragEnqueue(rbm->free_fragq,remove);
        }else if(option == AT_MTCP){
            RBFragEnqueue(rbm->free_fragq_int,remove);
        }
    }else if(len < buff->fctx->len){
        buff->fctx->seq += len;
        buff->fctx->len -= len;
    }else{
        assert(0);
    }
    return len;
}

j_stream_queue_int* CreateInternalStreamQueue(int size){
    j_stream_queue_int* sq;
    sq = (j_stream_queue_int*)calloc(1,sizeof(j_stream_queue_int));
    if(!sq){
        return NULL;
    }

    sq->array = (struct _j_tcp_stream**)calloc(size,sizeof(struct _j_tcp_stream*));
    if(!sq->array){
        free(sq);
        return NULL;
    }

    sq->size = size;
    sq->first = sq->last = 0;
    sq->count = 0;

    return sq;
}

void DestroyInternalStreamQueue(j_stream_queue_int* sq){
    if(!sq){
        return ;
    }
    if(sq->array){
        free(sq->array);
        sq->array = NULL;
    }
    free(sq);
}

int StreamInternalEnqueue(j_stream_queue_int* sq,struct _j_tcp_stream* stream){
    if(sq->count >= sq->size){
        printf("[WARNING] Queue overflow. Set larger queue size! "
                     "count: %d, size: %d\n", sq->count, sq->size);
    }
    sq->array[sq->last++] = stream;
    sq->count++;
    if(sq->last >= sq->size){
        sq->last = 0;
    }
    assert(sq->count <= sq->size);

    return 0;
}
struct _j_tcp_stream* StreamInternalDequeue(j_stream_queue_int* sq){
    struct _j_tcp_stream* stream = NULL;
    if(sq->count <= 0){
        return NULL;
    }

    stream = sq->array[sq->first++];
    assert(stream != NULL);

    if(sq->first >= sq->size){
        sq->first = 0;
    }
    sq->count--;
    assert(sq->count >= 0);

    return stream;
}

int StreamQueueIsEmpty(j_stream_queue* sq){
    return (sq->_head == sq->_tail);
}

j_stream_queue* CreateStreamQueue(int capacity){
    j_stream_queue* sq = NULL;

    sq = (j_stream_queue*)calloc(1,sizeof(j_stream_queue));
    if(!sq){
        return NULL;
    }
    sq->_q = (struct _j_tcp_stream**)calloc(capacity + 1,sizeof(struct _j_tcp_stream**));
    if(!sq->_q){
        free(sq);
        return NULL;
    }
    sq->_capacity = capacity;
    sq->_head = sq->_tail = 0;
    return sq;
}

void DestroyStreamQueue(j_stream_queue* sq){
    if(!sq){
        return ;
    }
    if(sq->_q){
        free((void*)sq->_q);
        sq->_q = NULL;
    }
    free(sq);
}

int StreamEnqueue(j_stream_queue* sq,struct _j_tcp_stream* stream){
    index_type h = sq->_head;
    index_type t = sq->_tail;
    index_type nt = NextIndex(sq,t);
    if(nt != h){
        sq->_q[t] = stream;
        MemoryBarrier(sq->_q[t],sq->_tail);
        sq->_tail = nt;
        return 0;
    }
    printf("Exceed capacity of stream queue.\n");
    return -1;
}

struct _j_tcp_stream* StreamDequeue(j_stream_queue* sq){
    index_type h = sq->_head;
    index_type t = sq->_tail;

    if(h != t){
        struct _j_tcp_stream* stream = sq->_q[h];
        MemoryBarrier(sq->_q[h],sq->_head);
        sq->_head = NextIndex(sq,h);
        assert(stream);
        return stream;
    }

    return NULL;
}
