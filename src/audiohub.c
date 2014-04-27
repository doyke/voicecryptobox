#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <string.h>


#define NETBUF_SIZE 4096
static char buf[NETBUF_SIZE];

fd_set active_ips, active_ops;
fd_set ips, ops;
int listener;
int peers;
int peer1 = -1;
int peer2 = -1;
int hubport;

static int create_listener_sock(void)
{
  int ret, listenfd;
  struct sockaddr_in servaddr;
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servaddr.sin_port=htons(hubport);
  listenfd = socket(AF_INET, SOCK_STREAM, 0);

  int yes = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
  ret = bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)); 
  
  if (ret < 0) {
    perror("couldn't create control listener sock\n");
    close(listenfd);
    return ret;
  }
  
  listen(listenfd, 10); 

  return listenfd;
}

static int get_maxfd(void)
{
  int tmp;

  tmp = listener;

  if (peer1 > tmp)
    tmp = peer1;
  if (peer2 > tmp)
    tmp = peer2;

  return tmp;

}

static void hub_notify(void)
{

  if (peer1 > 0 && peer2 > 0) {
    send(peer1, "2", 1, MSG_NOSIGNAL);
    send(peer2, "2", 1, MSG_NOSIGNAL);
    return;
  }
  
  if (peer1 > 0)
    send(peer1, "1", 1, MSG_NOSIGNAL);

  if (peer2 > 0)
    send(peer2, "1", 1, MSG_NOSIGNAL);

}
static void accept_peer(void)
{

  int flag = 1;
  int sendbuff=4096;
  int rcvbuff=4096;

  int fd = accept(listener, (struct sockaddr*)NULL, NULL); 
  if (fd < 0) {
    perror("accept() failed");
    return;
  }
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));

  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));    

  if (peer1 < 0) 
    peer1 = fd;  
  else 
    peer2 = fd;
  
  peers++;
  FD_SET(fd, &active_ips);
  FD_SET(fd, &active_ops);

  printf("audiohub: peer connect, %d peers connected\n", peers);
  if (peers ==2)
    FD_CLR(listener, &active_ips);

  hub_notify();

}

#if 0
static void peer_hangup(int *fd)
{
  
  close(*fd);

  FD_CLR(*fd, &active_ips);
  FD_CLR(*fd, &active_ops);
  *fd = -1;
  peers--;
  FD_SET(listener, &active_ips);
  printf("audiohub: peer hangup, %d peers connected\n", peers);
  hub_notify();
}
#endif
static void peer_hangup(void)
{
  
  if (peer1 >= 0) {
    close(peer1);
    FD_CLR(peer1, &active_ips);
    peer1 = -1;
  }
  if (peer2 >= 0) {
    close(peer2);
    FD_CLR(peer2, &active_ips);
    peer2 = -1;
  }

  peers = 0;
  FD_SET(listener, &active_ips);
  printf("audiohub: peer hangup, %d peers connected\n", peers);
  hub_notify();
}

static int peer_io(int *infd, int *outfd)
{
  int n;
  n = recv(*infd, buf, NETBUF_SIZE, 0);
  if (n <= 0) {
    peer_hangup();
    return -1;
  }
  
  n = send(*outfd, buf, n, MSG_NOSIGNAL);
  if (n < 0) {
    peer_hangup();
    return -1;
  }

  return 0;
}

int main(int argc, char **argv)
{

  int ret;

  if (argc < 2) {
    printf("usage: audiohub <port>\n");
    exit(1);
  }
  hubport = atoi(argv[1]);

  printf("audiohub running.\n");

  FD_ZERO(&active_ips);
  FD_ZERO(&active_ops);

  listener = create_listener_sock();
  if (listener < 0)
    exit(1);

  FD_SET(listener, &active_ips);
  while (1) {

    memcpy(&ips, &active_ips, sizeof(fd_set));
    memcpy(&ops, &active_ops, sizeof(fd_set));
       
    if ((ret = select(get_maxfd()+1, &ips, &ops, NULL, NULL)) < 0) {
      perror("select() failed");      
      continue;
    }

    if (peer1 >= 0 && FD_ISSET(peer1, &ips) && peer2 < 0) {
      peer_hangup();
    }

    if (peer2 >= 0 && FD_ISSET(peer2, &ips) && peer1 < 0) {
      peer_hangup();
    }

    if (peers < 2 && FD_ISSET(listener, &ips)) 
      accept_peer();

    if (peers < 2)
      continue;

    if (FD_ISSET(peer1, &ips) && FD_ISSET(peer2, &ops))
	if (peer_io(&peer1, &peer2) < 0)
	  continue;
	
    if (FD_ISSET(peer1, &ops) && FD_ISSET(peer2, &ips))
	if (peer_io(&peer2, &peer1) < 0)
	  continue;
  }

  return 0;
}
