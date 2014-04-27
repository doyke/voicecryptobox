/** 
 *  Copyright (C) 2013                                                        
 *    Mika Penttilä (mika.penttila@gmail.com)                                  
 *    Pasi Patama   (ppatama@kolumbus.fi)                                   
 *  
 **/

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "peer.h"

#define NETBUF_SIZE 4096
static char netbuf[NETBUF_SIZE];

extern int _use_ssl;
extern char certfile[];
extern char keyfile[];
extern char cafile[];

#define RANDOM_FILE "/dev/urandom"

int get_nonse(char *buf)
{
  int n;
  int fd = open(RANDOM_FILE, O_RDONLY);
  if (fd < 0)
    return fd;

  n = read(fd, buf, NONSE_LENGTH);
  if (n < NONSE_LENGTH) 
    n = -1;

  close(fd);
  return n;
}

int check_cert(hub_peer_t *hp, SSL *ssl)
{
  X509 *sslpeer;
  
  sslpeer = SSL_get_peer_certificate(ssl);
  
  if (sslpeer) {
    if (SSL_get_verify_result(ssl)!=X509_V_OK) {
      ERR_print_errors_fp (stderr);
      return -1;
    }
    X509_NAME_get_text_by_NID(X509_get_subject_name(sslpeer), NID_commonName, hp->common_name, 256);
    printf("peer = %s\n", hp->common_name);
    X509_free(sslpeer);
  } else {
    printf("no peer\n");
    return -1;
  }

  return 0;
}

static int ssl_init(hub_peer_t *hp, int iscontrol)
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
    curctx = &hp->control_ctx;
    curssl = &hp->control_ssl;
  }
  else {
    curctx = &hp->ctx;
    curssl = &hp->ssl;
  }

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

  if (!SSL_set_fd (*curssl, iscontrol ? hp->control_fd : hp->fd)) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if((ret = SSL_accept(*curssl)) <=0 ) {
    ERR_print_errors_fp(stderr);
    printf("ssl error %d\n", SSL_get_error(*curssl, ret));
    return -1;
  }        
  
  return check_cert(hp, *curssl);
}

static void ssl_hangup(SSL_CTX *ctx, SSL *ssl) 
{
  if (ssl) {
    SSL_shutdown (ssl);
    SSL_free (ssl);
  }
  if (ctx) {
    SSL_CTX_free (ctx);
  }
}

void ssl_stream_hangup(hub_peer_t *hp)
{
  ssl_hangup(hp->ctx, hp->ssl);
}

void ssl_control_hangup(hub_peer_t *hp)
{
  ssl_hangup(hp->control_ctx, hp->control_ssl);
}

int ssl_stream_init(hub_peer_t *hp)
{
  return ssl_init(hp, 0);
}

int ssl_control_init(hub_peer_t *hp)
{
  return ssl_init(hp, 1);
}

int hubnet_pipe_to_sock(hub_peer_t *hp)
{
  int n;
  n = read(hp->pipe_to_peer[0], netbuf, NETBUF_SIZE);
  if (n <=0)
    return n;
  if (_use_ssl)
    n = SSL_write(hp->ssl, netbuf, n);
  else
    n = send(hp->fd, netbuf, n, MSG_NOSIGNAL);
  return n;

}

int hubnet_sock_to_pipe(hub_peer_t *hp)
{
  int n;

  if (_use_ssl)
    n = SSL_read(hp->ssl, netbuf, NETBUF_SIZE);
  else
    n = recv(hp->fd, netbuf, NETBUF_SIZE, 0);
  if (n <= 0)
    return n;

  n = write(hp->pipe_from_peer[1], netbuf, n);
  return n;
}

int hubnet_ctrl_read(hub_peer_t *hp, char *buf, int n)
{

  if (_use_ssl)
    n = SSL_read(hp->control_ssl, buf, n);
  else
    n = recv(hp->control_fd, buf, n, 0);
  
  return n;
}

int hubnet_ctrl_write(hub_peer_t *hp, char *buf, int n)
{
  if (_use_ssl)
    n = SSL_write(hp->control_ssl, buf, n);
  else
    n = send(hp->control_fd, buf, n, MSG_NOSIGNAL);
  return n;

}

int hubnet_read(hub_peer_t *hp, char *buf, int n)
{

  if (_use_ssl)
    n = SSL_read(hp->ssl, buf, n);
  else
    n = recv(hp->fd, buf, n, 0);
  
  return n;
}

int hubnet_write(hub_peer_t *hp, char *buf, int n)
{
  if (_use_ssl)
    n = SSL_write(hp->ssl, buf, n);
  else
    n = send(hp->fd, buf, n, MSG_NOSIGNAL);
  return n;

}
