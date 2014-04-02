/**
 *  Copyright (C) 2013                                                          *
 *    Mika Penttilä (mika.penttila@gmail.com)                                  
 *    Pasi Patama   (ppatama@kolumbus.fi)                                       *
 *  
 **/

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

extern char role[];
extern char peer[];
extern char port[];
extern char proto[];
extern char certfile[];
extern char keyfile[];
extern char cafile[];

#define NETBUF_SIZE 4096
static char netbuf[NETBUF_SIZE];

extern int _use_ssl;
SSL *ssl;
SSL *control_ssl;
SSL_CTX *ctx;
SSL_CTX *control_ctx;
char peer_CN[256];

int check_cert(SSL *ssl)
{
  X509 *sslpeer;
  
  sslpeer = SSL_get_peer_certificate(ssl);
  
  if (sslpeer) {
    if (SSL_get_verify_result(ssl)!=X509_V_OK) {
      ERR_print_errors_fp (stderr);
      return -1;
    }
    X509_NAME_get_text_by_NID(X509_get_subject_name(sslpeer), NID_commonName, peer_CN, 256);
    printf("peer = %s\n", peer_CN);
    X509_free(sslpeer);
  } else {
    printf("no peer\n");
    return -1;
  }

  return 0;
}

/* caller == ssl client, !client == ssl server */
int ssl_init(int caller, int fd, int iscontrol)
{
  const SSL_METHOD *method;
  int ret;
  SSL_CTX **curctx;
  SSL **curssl;
  if (!_use_ssl)
    return 0;

  SSL_library_init ();
  SSL_load_error_strings ();

  if (iscontrol) {
    curctx = &control_ctx;
    curssl = &control_ssl;
  }
  else {
    curctx = &ctx;
    curssl = &ssl;
  }
#if 0
  if (caller)
    //    method = SSLv23_client_method();
    method = TLSv1_1_client_method();
  else
    //method = SSLv23_method();
    method = TLSv1_1_server_method();
#endif
  method = SSLv23_method();
  *curctx = SSL_CTX_new (method);

  if (*curctx == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* Load cert */
  if(!(SSL_CTX_use_certificate_file(*curctx, certfile, SSL_FILETYPE_PEM))) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* Load private key */
  if(!(SSL_CTX_use_PrivateKey_file(*curctx, keyfile, SSL_FILETYPE_PEM))) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  
  /* Load the CAs we trust*/
  if(!(SSL_CTX_load_verify_locations(*curctx, cafile, 0))) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* if in server role request peer's cert */
  //if (!caller)
  SSL_CTX_set_verify(*curctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE, 0);
  
  SSL_CTX_set_verify_depth(*curctx, 1);

  STACK_OF(X509_NAME) *cert_names;

  cert_names = SSL_load_client_CA_file(cafile);
  if (cert_names != NULL) {
    printf("loaded client ca list\n");
    SSL_CTX_set_client_CA_list(*curctx, cert_names);
  } else
    printf("not loaded client ca list\n");
  SSL_CTX_set_mode(*curctx, SSL_MODE_AUTO_RETRY);
  *curssl = SSL_new(*curctx);
  if (*curssl == NULL) {
      ERR_print_errors_fp(stderr);
      return -1;
  }

  if (!SSL_set_fd (*curssl, fd)) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (caller) {
    if (SSL_connect (*curssl) != 1) {
      ERR_print_errors_fp(stderr);
      printf("ssl error %d\n", SSL_get_error(*curssl, ret));
      return -1;
    }
  } else {
    if((ret = SSL_accept(*curssl)) <=0 ) {
      ERR_print_errors_fp(stderr);
      printf("ssl error %d\n", SSL_get_error(*curssl, ret));
      return -1;
    }        
  }

  return check_cert(*curssl);
    
}

int net_control_read(int fd, char *buf, int n) {

  if (_use_ssl)
    n = SSL_read(control_ssl, buf, n);
  else
    n = recv(fd, buf, n, 0);

  return n;
}

static int net_control_write(int fd, char *buf, int n)
{
  if (_use_ssl)
    n = SSL_write(control_ssl, buf, n);
  else
    n = send(fd, buf, n, MSG_NOSIGNAL);
  return n;
}

int send_identity(int fd, char *id)
{
  if (!_use_ssl)
    return send(fd, id, strlen(id), MSG_NOSIGNAL);
  else
    return 0;
}

int send_nonse(int fd, char *buf, int n)
{
  return send(fd, buf, n, MSG_NOSIGNAL);
}

int hub_make_call(int fd, char *fifoargs)
{
  char tmpbuf[256];
  int i = strlen(fifoargs);
  memset(tmpbuf, 0, 256);
  tmpbuf[0] = 'C';
  tmpbuf[1] = i;
  strncat(&tmpbuf[2], fifoargs, 253);
  printf("%02x %02x %02x\n", tmpbuf[0], tmpbuf[1], tmpbuf[2]);
  if (net_control_write(fd, tmpbuf, i+2) < 0) 
    return -1;
  return 0;
}

char *net_get_caller_id(void)
{
  if (_use_ssl)
    return peer_CN;
  else
    return NULL;
}

const char *net_get_cipher(void)
{
  if (_use_ssl) {
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher)
      return SSL_CIPHER_get_name(cipher);
    else
      return "unencrypted";
  }
  else
    return "unencrypted";

}

void net_hangup(void)
{
  if (!_use_ssl)
    return;

  if (ssl) {
    SSL_shutdown (ssl);
    SSL_free (ssl);
    ssl = NULL;
  }
  if (ctx) {
    SSL_CTX_free (ctx);
    ctx = NULL;
  }
}

int net_connect(int control) 
{
  int sockfd = -1; 
  int flag = 1;
#if 1
  int sendbuff=4096;
  int rcvbuff=4096;
  int clamp=2048;
#endif

  struct sockaddr_in servaddr;
  
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(peer);
  servaddr.sin_port = control ? htons(atoi(port)-1) : htons(atoi(port));

  if (!strcmp(proto, "udp")) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
  } else {
    /* tcp */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

#if 1
  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));
  //setsockopt(sockfd, SOL_SOCKET, TCP_WINDOW_CLAMP, (char *)&clamp, sizeof(clamp));
#endif
  setsockopt(sockfd,          
	     IPPROTO_TCP,     
	     TCP_NODELAY,     
	     (char *) &flag,               
	     sizeof(int));    

  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    close(sockfd);
    return -1;
  }

  return sockfd;
}

int net_listen(void) 
{
  int sockfd;
  struct sockaddr_in servaddr;
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servaddr.sin_port=htons(atoi(port));


  if (!strcmp(proto, "udp")) {

    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
    
    return sockfd;
  }
  else {
    /* tcp */
    int listenfd = 0, connfd = 0, ret;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    int yes = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    ret = bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)); 

    if (ret < 0) {
      close(listenfd);
      return ret;
    }
    
    listen(listenfd, 10); 

    connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
    close(listenfd);
    return connfd;
  }
}

int create_stream_listener_sock(void)
{
  int ret, listenfd;
  struct sockaddr_in servaddr;
  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servaddr.sin_port=htons(atoi(port));
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

int create_stream_sock(char *_role, int control)
{
  if (!strcmp(_role, "initiator") || !strcmp(role, "initiator"))
    return net_connect(control);
  else 
    return net_listen();
}

static int net_read(int streamfd, int outfd)
{
  int n;

  if (_use_ssl)
    n = SSL_read(ssl, netbuf, NETBUF_SIZE);
  else
    n = recv(streamfd, netbuf, NETBUF_SIZE, 0);
  if (n <= 0)
    return n;

  n = write(outfd, netbuf, n);
  return n;

}

static int net_write(int streamfd, int infd)
{
  int n;
  n = read(infd, netbuf, NETBUF_SIZE);
  if (n <=0)
    return n;
  if (_use_ssl)
    n = SSL_write(ssl, netbuf, n);
  else
    n = send(streamfd, netbuf, n, MSG_NOSIGNAL);
  return n;
}

int send_guid(int streamfd)
{
  if (_use_ssl)
    return SSL_write(ssl, "ACK", 3);
  else
    return send(streamfd, "ACK", 3, MSG_NOSIGNAL);
}

int receive_guid(int streamfd)
{
  char tmp[3];
  int n;

  if (!_use_ssl) {
    n =  recv(streamfd, tmp, 3, 0);
    if (n <=0)
      return -1;
    return 1;
  }

  n =  SSL_read(ssl, tmp, 3);
  switch( SSL_get_error(ssl, n)) {
  case SSL_ERROR_NONE:
    return 1;
 case SSL_ERROR_ZERO_RETURN:
   return -1;

  }
  return 0;

}

int send_answer(int streamfd)
{

  if (_use_ssl)
    return SSL_write(ssl, "ANSWER", 6);
  else
    return send(streamfd, "ANSWER", 6, MSG_NOSIGNAL);
}

int receive_answer(int streamfd)
{
  char tmp[6];
  int n;

  if (!_use_ssl) {
    printf("receing answer\n");
    n =  recv(streamfd, tmp, 6, 0);
    if (n <=0)
      return -1;
    return 1;
	
  }

  n =  SSL_read(ssl, tmp, 6);
  switch( SSL_get_error(ssl, n)) {
  case SSL_ERROR_NONE:
    return 1;
  case SSL_ERROR_ZERO_RETURN:
   return -1;
  }
  return 0;
}


int run_established(fd_set *ips, fd_set *ops, int streamfd, int inpipe, int outpipe)
{
  int n = 0;
  
  if (streamfd < 0) {
    /* local loopback */
    if (FD_ISSET(inpipe, ips) && FD_ISSET(outpipe, ops)) {
      n = read(inpipe, netbuf, NETBUF_SIZE);
      n = write(outpipe, netbuf, n);		  
    }
    return n;
  }

  if (FD_ISSET(inpipe, ips) && FD_ISSET(streamfd, ops)) {
    n = net_write(streamfd, inpipe);
    if (n <= 0)
      return -1;
  }

  if (FD_ISSET(outpipe, ops) && FD_ISSET(streamfd, ips)) {
    n = net_read(streamfd, outpipe);
    if (n <= 0)
      return -1;
  }

  return n;

}
