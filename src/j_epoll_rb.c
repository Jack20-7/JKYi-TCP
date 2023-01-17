#include"j_tree.h"
#include"j_queue.h"
#include"j_epoll_inner.h"
#include"j_config.h"

#if J_ENABLE_EPOLL_RB

#include<pthread.h>
#include<stdint.h>
#include<time.h>

extern j_tcp_manager* j_get_tcp_manager();

int epoll_create(int size){
    if(size <= 0){
        return -1;
    }

    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    struct _j_socket* epsocket = j_socket_allocate(J_TCP_SOCK_EPOLL);
    if(epsocket == NULL){
        j_trace_epoll("malloc failed.\n");
        return -1;
    }

    struct eventpoll* ep = (struct eventpoll*)calloc(1,sizeof(struct eventpoll));
    if(!ep){
        j_free_socket(epsocket->id,0);
        return -1;
    }

    ep->rbcnt = 0;
    RB_INIT(&ep->rbr);
    LIST_INIT(&ep->rdlist);

    if(pthread_mutex_init(&ep->mtx,NULL)){
        free(ep);
        j_free_socket(epsocket->id,0);
        return -2;
    }

    if(pthread_mutex_init(&ep->cdmtx,NULL)){
        pthread_mutex_destroy(&ep->mtx);
        free(ep);
        j_free_socket(epsocket->id,0);
        return -2;
    } 

    if(pthread_cond_init(&ep->cond,NULL)){
        pthread_mutex_destroy(&ep->cdmtx);
        pthread_mutex_destroy(&ep->mtx);
        free(ep);
        j_free_socket(epsocket->id,0);
        return -2;
    }
    if(pthread_spin_init(&ep->lock,PTHREAD_PROCESS_SHARED)){
        pthread_cond_destroy(&ep->cond);
        pthread_mutex_destroy(&ep->cdmtx);
        pthread_mutex_destroy(&ep->mtx);
        free(ep);
        j_free_socket(epsocket->id,0);
        return -2;
    }

    tcp->ep = (void*)ep;
    epsocket->ep = (void*)ep;

    return epsocket->id;
}

int epoll_ctl(int epid,int op,int sockid,struct epoll_event* event){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    j_trace_epoll("epoll_ctl-->11111111:%d,sockid:%d\n",epid,sockid);
    struct _j_socket* epsocket = tcp->fdtable->sockfds[epid];
    if(epsocket->socktype == J_TCP_SOCK_UNUSED){
        errno = -EBADF;
        return -1;
    }

    if(epsocket->socktype != J_TCP_SOCK_EPOLL){
        errno = -EINVAL;
        return -1;
    }

    j_trace_epoll("epoll_ctl--->eventpoll\n");

    struct eventpoll* ep = (struct eventpoll*)epsocket->ep;
    if(!ep || (!event && op != EPOLL_CTL_DEL)){
        errno = -EINVAL;
        return -1;
    }

    if(op == EPOLL_CTL_ADD){
        pthread_mutex_lock(&ep->mtx);
        struct epitem tmp;
        tmp.sockfd = sockid;
        //查看要add的该文件描述符是否在红黑树中存在
        struct epitem* epi = RB_FIND(_epoll_rb_socket,&ep->rbr,&tmp);
        if(epi){
            j_trace_epoll("rbtree is exist\n");
            pthread_mutex_unlock(&ep->mtx);
            return -1;
        }

        epi = (struct epitem*)calloc(1,sizeof(struct epitem));
        if(!epi){
            pthread_mutex_unlock(&ep->mtx);
            errno = -ENOMEM;
            return -1;
        }

        epi->sockfd = sockid;
        memcpy(&epi->event,event,sizeof(struct epoll_event));

        epi = RB_INSERT(_epoll_rb_socket,&ep->rbr,epi);
        assert(epi == NULL);

        ep->rbcnt++;
        pthread_mutex_unlock(&ep->mtx);
    }else if(op == EPOLL_CTL_DEL){
        pthread_mutex_lock(&ep->mtx);

        struct epitem tmp;
        tmp.sockfd = sockid;
        struct epitem* epi = RB_FIND(_epoll_rb_socket,&ep->rbr,&tmp);

        if(!epi){
            j_trace_epoll("rbtree is no exist!\n");
            pthread_mutex_unlock(&ep->mtx);
            return -1;
        }

        epi = RB_REMOVE(_epoll_rb_socket,&ep->rbr,epi);
        if(!epi){
            j_trace_epoll("rbtree is no exist!\n");
            pthread_mutex_unlock(&ep->mtx);
            return -1;
        }
        ep->rbcnt--;
        free(epi);
        pthread_mutex_unlock(&ep->mtx);
    }else if(op == EPOLL_CTL_MOD){
        struct epitem tmp;
        tmp.sockfd = sockid;
        struct epitem* epi = RB_FIND(_epoll_rb_socket,&ep->rbr,&tmp);
        if(epi){
            epi->event.events = event->events;
            epi->event.events |= EPOLLERR | EPOLLHUP;
        }else{
            errno = -ENOENT;
            return -1;
        }
    }else{
        j_trace_epoll("op is no exist!\n");
        assert(0);
    }

    return 0;
}

int epoll_wait(int epid,struct epoll_event* events,int maxevents,int timeout){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    struct _j_socket* epsocket =  tcp->fdtable->sockfds[epid];
    if(!epsocket){
        return -1;
    }

    if(epsocket->socktype == J_TCP_SOCK_UNUSED){
        errno = -EBADF;
        return -1;
    }

    if(epsocket->socktype != J_TCP_SOCK_EPOLL){
        errno = -EINVAL;
        return -1;
    }

    struct eventpoll* ep = epsocket->ep;
    if(!ep || !events || maxevents <= 0){
        errno = -EINVAL;
        return -1;
    }

    if(pthread_mutex_lock(&ep->cdmtx)){
        if(errno == EDEADLK){
            j_trace_epoll("epoll lock blocked!\n");
        }
        assert(0);
    }

    while(ep->rdnum == 0 && timeout != 0){
        ep->waiting = 1;
        if(timeout > 0){
            struct timespec deadline;
            clock_gettime(CLOCK_REALTIME,&deadline);
            if(timeout >= 1000){
                int sec = timeout / 1000;
                deadline.tv_sec += sec;
                timeout -= sec * 1000;
            }

            deadline.tv_nsec += timeout * 1000000;
            if(deadline.tv_nsec >= 1000000000){
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }

            int ret = pthread_cond_timedwait(&ep->cond,&ep->cdmtx,&deadline);
            if(ret && ret != ETIMEDOUT){
                j_trace_epoll("pthread_cond_timewait\n");
                pthread_mutex_unlock(&ep->cdmtx);

                return -1;
            }
            timeout = 0;
        }else if(timeout < 0){
            int ret = pthread_cond_wait(&ep->cond,&ep->cdmtx);
            if(ret){
                j_trace_epoll("pthread_cond_wait\n");
                pthread_mutex_unlock(&ep->cdmtx);
                return -1;
            }
        }
        ep->waiting = 0;
    }

    pthread_mutex_unlock(&ep->cdmtx);

    //下面就是将就绪队列中的事件拷贝到传出参数里面去
    pthread_spin_lock(&ep->lock);

    int cnt = 0;
    int num = (ep->rdnum > maxevents ? maxevents : ep->rdnum);
    int i = 0;

    while(num != 0 && !LIST_EMPTY(&ep->rdlist)){     //ET
        struct epitem* epi = LIST_FIRST(&ep->rdlist);
        LIST_REMOVE(epi,rdlink);
        epi->rdy = 0;

        memcpy(&events[i++],&epi->event,sizeof(struct epoll_event));
        
        num--;
        cnt++;
        ep->rdnum--;
    }

    pthread_spin_unlock(&ep->lock);

    return cnt;
}

//回调函数
int epoll_event_callback(struct eventpoll* ep,int sockid,uint32_t event){
    struct epitem tmp;
    tmp.sockfd = sockid;

    struct epitem* epi = RB_FIND(_epoll_rb_socket,&ep->rbr,&tmp);
    if(!epi){
        j_trace_epoll("rbtree not exist!\n");
        assert(0);
    }

    if(epi->rdy){
        //如果该sockid上已有事件发生
        epi->event.events |= event;
        return 1;
    }

    j_trace_epoll("epoll_event_callback-->%d\n",epi->sockfd);

    pthread_spin_lock(&ep->lock);
    epi->rdy = 1;
    LIST_INSERT_HEAD(&ep->rdlist,epi,rdlink);
    ep->rdnum++;
    pthread_spin_unlock(&ep->lock);

    //将epoll_wait给唤醒
    pthread_mutex_lock(&ep->cdmtx);
    pthread_cond_signal(&ep->cond);
    pthread_mutex_unlock(&ep->cdmtx);

    return 0;
}

static int epoll_destroy(struct eventpoll* ep){
    while(!LIST_EMPTY(&ep->rdlist)){
        struct epitem* epi = LIST_FIRST(&ep->rdlist);
        LIST_REMOVE(epi,rdlink);
    }

    pthread_mutex_lock(&ep->mtx);

    while(1){
        struct epitem* epi = RB_MIN(_epoll_rb_socket,&ep->rbr);
        if(epi == NULL){
            break;
        }

        epi = RB_REMOVE(_epoll_rb_socket,&ep->rbr,epi);
        free(epi);
    }
    pthread_mutex_unlock(&ep->mtx);

    return 0;
}

int j_epoll_close_socket(int epid){
    j_tcp_manager* tcp = j_get_tcp_manager();
    if(!tcp){
        return -1;
    }

    struct eventpoll* ep = (struct eventpoll*)tcp->fdtable->sockfds[epid]->ep;
    if(!ep){
        errno = -EINVAL;
        return -1;
    }

    epoll_destroy(ep);

    pthread_mutex_lock(&ep->mtx);
    tcp->ep = NULL;
    tcp->fdtable->sockfds[epid]->ep = NULL;
    pthread_cond_signal(&ep->cond);
    pthread_mutex_unlock(&ep->mtx);

    pthread_cond_destroy(&ep->cond);
    pthread_mutex_destroy(&ep->mtx);
    pthread_spin_destroy(&ep->lock);

    free(ep);

    return 0;
}






#endif
