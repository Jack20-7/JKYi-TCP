#ifndef _JKYI_TCP_API_H_
#define _JKYI_TCP_API_H_

#include<sys/types.h>
#include<sys/socket.h>


int j_socket(int domain,int type,int protocol);
int j_bind(int sockfd,const struct sockaddr* addr,socklen_t addrlen);
int j_listen(int sockfd,int backlog);
int j_accept(int sockfd,struct sockaddr* addr,socklen_t* addrlen);
ssize_t j_recv(int sockfd,char* buf,size_t len,int flags);
ssize_t j_send(int sockfd,const char* buf,size_t len);
int j_close(int sockfd);

void j_tcp_setup(void);

int socket(int domain,int type,int protocol);
int bind(int sockfd,const struct sockaddr* addr,socklen_t addrlen);
int listen(int sockfd,int backlog);
int accept(int sockfd,struct sockaddr* addr,socklen_t* addrlen);
ssize_t recv(int sockfd,void* buf,size_t len,int flags);
ssize_t send(int sockfd,const void* buf,size_t len,int flags);

#endif
