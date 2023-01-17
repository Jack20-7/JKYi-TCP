#include"j_epoll_inner.h"
#include"j_header.h"
#include"j_socket.h"

#include<hugetlbfs.h>
#include<pthread.h>
#include<errno.h>

extern j_tcp_manager* j_get_tcp_manager();

j_socket_map* j_allocate_socket(int socktype,int need_lock){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(tcp == NULL){
        assert(0);
        return NULL;
    }

    if(need_lock){
        pthread_mutex_lock(&tcp->ctx->smap_lock);
    }

    j_socket_map* socket = NULL;
    while(socket == NULL){
        socket = TAILQ_FIRST(&tcp->free_smap);
        if(!socket){
            if(need_lock){
                pthread_mutex_unlock(&tcp->ctx->smap_lock);
            }
            printf("The concurrent sockets are max!\n");
            return NULL;
        }
        TAILQ_REMOVE(&tcp->free_smap,socket,free_smap_link);
        if(socket->events){
            printf("There are still not invalidate events remaing.\n");
            TAILQ_INSERT_TAIL(&tcp->free_smap,socket,free_smap_link);
            socket = NULL;
        }
    }

    if(need_lock){
        pthread_mutex_unlock(&tcp->ctx->smap_lock);
    }

    socket->socktype = socktype;
    socket->opts = 0;
    socket->stream = NULL;
    socket->epoll = 0;
    socket->events = 0;

    memset(&socket->s_addr,0,sizeof(struct sockaddr_in));
    memset(&socket->ep_data,0,sizeof(uint64_t));

    return socket;
}

void j_free_socket(int sockid,int need_lock){
    j_tcp_manager* tcp = j_get_tcp_manager();
    j_socket_map* socket = &tcp->smap[sockid];

    if(socket->socktype == J_TCP_SOCK_UNUSED){
        return;
    }

    socket->socktype = J_TCP_SOCK_UNUSED;
    socket->epoll = J_EPOLLNONE;
    socket->events = J_EPOLLNONE;

    if(need_lock){
        pthread_mutex_lock(&tcp->ctx->smap_lock);
    }
    tcp->smap[sockid].stream = NULL;
    TAILQ_INSERT_TAIL(&tcp->free_smap,socket,free_smap_link);
    if(need_lock){
        pthread_mutex_unlock(&tcp->ctx->smap_lock);
    }
}

j_socket_map* j_get_socket(int sockid){
    if(sockid < 0 || sockid >= J_MAX_CONCURRENCY){
        errno = EBADF;
        return NULL;
    }

    j_tcp_manager* tcp = j_get_tcp_manager();
    j_socket_map* socket = &tcp->smap[sockid];

    return socket;
}
struct _j_socket_table* j_socket_allocate_fdtable(){
    struct _j_socket_table* sock_table = 
                (struct _j_socket_table*)calloc(1,sizeof(struct _j_socket_table));
    if(sock_table == NULL){
        errno = -ENOMEM;
        return NULL;
    }


    size_t total_size = J_SOCKFD_NR * sizeof(struct _j_socket*);
    int ret = posix_memalign((void**)&sock_table->sockfds,getpagesize(),total_size);
    if(ret != 0){
        errno = -ENOMEM;
        free(sock_table);
        return NULL;
    }

    sock_table->max_fds = (J_SOCKFD_NR % J_BITS_PER_BYTE ? 
                                     J_SOCKFD_NR / J_BITS_PER_BYTE + 1
                                     : J_SOCKFD_NR / J_BITS_PER_BYTE);
    sock_table->open_fds = (unsigned char*)calloc(sock_table->max_fds,
                                                    sizeof(unsigned char)); 
    if(sock_table->open_fds == NULL){
        errno = -ENOMEM;
        free(sock_table->sockfds);
        free(sock_table);
        return NULL;
    }

    if(pthread_spin_init(&sock_table->lock,PTHREAD_PROCESS_SHARED)){
        errno = -EINVAL;
        free(sock_table->open_fds);
        free(sock_table->sockfds);
        free(sock_table);
        return NULL;
    }

    return sock_table;
}

void j_socket_free_fdtable(struct _j_socket_table* fdtable){
    pthread_spin_destroy(&fdtable->lock);
    free(fdtable->open_fds);
    free(fdtable->sockfds);
    free(fdtable);
}

struct _j_socket_table* j_socket_get_fdtable(){
    j_tcp_manager* tcp = j_get_tcp_manager();
    assert(tcp != NULL);

    return tcp->fdtable;
}

struct _j_socket_table* j_socket_init_fdtable(){
    return j_socket_allocate_fdtable();
}

int j_socket_find_id(unsigned char* fds,int start,size_t max_fds){
    size_t i = 0;
    for(i = start;i < max_fds;++i){
        if(fds[i] != 0xFF){
            break;
        }
    }

    if(i == max_fds){
        return -1;
    }

    int j = 0;
    char byte = fds[i];
    while(byte % 2){
        byte /= 2;
        j++;
    }
    return i * J_BITS_PER_BYTE + j;
}

//消除对应位上的1
char j_socket_unuse_id(unsigned char* fds,size_t idx){
    int i = idx / J_BITS_PER_BYTE;
    int j = idx % J_BITS_PER_BYTE;
    char byte = 0x01 << j;
    fds[i] &= ~byte;

    return fds[i];
}

int j_socket_set_start(size_t idx){
    return idx / J_BITS_PER_BYTE;
}

//将对应的位设置为1
char j_socket_use_id(unsigned char* fds,size_t idx){
    int i = idx / J_BITS_PER_BYTE;
    int j = idx % J_BITS_PER_BYTE;

    char byte = 0x01 << j;
    fds[i] |= byte;

    return fds[i];
}

struct _j_socket* j_socket_allocate(int socktype){
    struct _j_socket*s = (struct _j_socket*)calloc(1,sizeof(struct _j_socket));
    if(s == NULL){
        errno = -ENOMEM;
        return NULL;
    }

    struct _j_socket_table* sock_table = j_socket_get_fdtable();
    pthread_spin_lock(&sock_table->lock);

    s->id = j_socket_find_id(sock_table->open_fds,sock_table->cur_idx,sock_table->max_fds);
    if(s->id == -1){
        pthread_spin_unlock(&sock_table->lock);
        errno = -ENFILE;
        return NULL;
    }

    sock_table->cur_idx = j_socket_set_start(s->id);
    char byte = j_socket_use_id(sock_table->open_fds,s->id);
    sock_table->sockfds[s->id] = s;
    j_trace_tcp("j_socket_allocate-->j_socket_use_id:%x\n",byte);

    pthread_spin_unlock(&sock_table->lock);

    s->socktype = socktype;
    s->opts = 0;
    s->socktable = sock_table;
    s->stream = NULL;

    memset(&s->s_addr,0,sizeof(struct sockaddr_in));

    UNUSED(byte);

    return s;
}

void j_socket_free(int sockid){
    struct _j_socket_table * sock_table = j_socket_get_fdtable();

    struct _j_socket* s = sock_table->sockfds[sockid];
    sock_table->sockfds[sockid] = NULL;

    pthread_spin_lock(&sock_table->lock);
    char byte = j_socket_unuse_id(sock_table->open_fds,sockid);

    sock_table->cur_idx = j_socket_set_start(sockid);
    j_trace_tcp("j_socket_free-->j_socket_unuse_id:%x,%d\n",
                   byte,sock_table->cur_idx);

    pthread_spin_unlock(&sock_table->lock);
    free(s);

    UNUSED(byte);

    j_trace_tcp("j_socket_free---Exit\n");

    return ;
}

struct _j_socket* j_socket_get(int sockid){
    struct _j_socket_table* sock_table = j_socket_get_fdtable();
    if(sock_table == NULL){
        return NULL;
    }

    return sock_table->sockfds[sockid];
}

int j_socket_close_stream(int sockid){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    struct _j_socket* s = j_socket_get(sockid);
    if(s == NULL){
        return -1;
    }

    j_tcp_stream* cur_stream = s->stream;
    if(!cur_stream){
        j_trace_api("Socket %d:stream does not exist.\n",sockid);
        errno = -ENOTCONN;
        return -1;
    }

    if(cur_stream->closed){
        j_trace_api("Socket %d:(Stream %u):already closed stream.\n",
                      sockid,cur_stream->id);
        return 0;
    }

    cur_stream->closed = 1;

    j_trace_api("Stream %d:closing the stream.\n",cur_stream->id);
    cur_stream->s = NULL;

    if(cur_stream->state == J_TCP_CLOSED){
        printf("Stream %d at TCP_ST_CLOSED. destroying the stream.\n", 
                     cur_stream->id);
        StreamEnqueue(tcp->destroyq,cur_stream);
        tcp->wakeup_flag = 1;
        return 0;
    }else if(cur_stream->state == J_TCP_SYN_SENT){
        StreamEnqueue(tcp->destroyq,cur_stream);
        tcp->wakeup_flag = 1;

        return -1;
    }else if(cur_stream->state != J_TCP_ESTABLISHED && 
                 cur_stream->state != J_TCP_CLOSE_WAIT){
        j_trace_api("Stream %d at state %d\n",
                       cur_stream->id,cur_stream->state);
        errno = -EBADF;
        return -1;
    }

    cur_stream->snd->on_closeq = 1;
    int ret = StreamEnqueue(tcp->closeq,cur_stream);
    tcp->wakeup_flag = 1;

    if(ret < 0){
        j_trace_api("(NEVER HAPPEN) Failed to enqueue the stream to closeq.\n");
        errno = -EAGAIN;
        return -1;
    }

    return 0;
}
int j_socket_close_listening(int sockid){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    struct _j_socket*s = j_socket_get(sockid);
    if(s == NULL){
        return -1;
    }

    struct _j_tcp_listener* listener = s->listener;
    if(!listener){
        errno = EINVAL;
        return -1;
    }

    if(listener->acceptq){
        DestroyStreamQueue(listener->acceptq);
        listener->acceptq = NULL;
    }

    pthread_mutex_lock(&listener->accept_lock);
    pthread_cond_signal(&listener->accept_cond);
    pthread_mutex_unlock(&listener->accept_lock);

    pthread_cond_destroy(&listener->accept_cond);
    pthread_mutex_destroy(&listener->accept_lock);

    free(listener);
    s->listener = NULL;

    return 0;
}




