#ifndef _PEER_H_
#define _PEER_H_

#include <sys/time.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include "list.h"

#define MAX_PEERS 8
#define MAX_CN_LENGTH 256

/* 20ms of mono audio at 48k */
#define MIXBUF_SIZE 1920
#define NONSE_LENGTH 16

typedef enum _peer_type_t {
  peer_normal,
  peer_conference,
} peer_type_t;

typedef enum _peer_status_t {
  peer_status_available,
  peer_status_busy,
} peer_status_t;

struct _call_t;

typedef struct _hub_peer_t {
  struct list_head head;
  struct list_head peer_call;
  int fd;
  int control_fd;
  SSL *ssl;
  SSL_CTX *ctx;
  SSL *control_ssl;
  SSL_CTX *control_ctx;
  char nonse[NONSE_LENGTH];
  int handshake_complete;
  int pipe_from_peer[2];
  int pipe_to_peer[2];
  int mixpipe_to_peer[2];
  int mixpipe_from_peer[2];
  pid_t encoder, decoder;;
  char common_name[MAX_CN_LENGTH];
  int16_t intbuf[MIXBUF_SIZE/2];
  peer_type_t type;
  peer_status_t status;
  struct _call_t *active_call;
} hub_peer_t;

struct list_head peerlist;
extern hub_peer_t *conference_peer;

void remove_dup_peers(const hub_peer_t *hp);
hub_peer_t *find_peer(const char *cn);
hub_peer_t *find_peer_by_nonse(const char *nonse);
hub_peer_t *add_peer(int fd, peer_type_t type, const char *cn);
int remove_peer(hub_peer_t *hp);
int peer_count(void);
void peer_hangup(hub_peer_t *hp) ;

int create_conf_peer(void);

extern void reset_peer(hub_peer_t *hp);
#endif
