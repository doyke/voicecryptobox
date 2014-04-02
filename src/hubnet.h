#ifndef _HUBNET_H_
#define _HUBNET_H_

#include "peer.h"

#define RANDOM_FILE /dev/urandom

int ssl_stream_init(hub_peer_t *hp);
int ssl_control_init(hub_peer_t *hp);
void ssl_stream_hangup(hub_peer_t *hp);
void ssl_control_hangup(hub_peer_t *hp);
int hubnet_pipe_to_sock(hub_peer_t *hp);
int hubnet_sock_to_pipe(hub_peer_t *hp);
int hubnet_ctrl_read(hub_peer_t *hp, char *buf, int n);
int hubnet_ctrl_write(hub_peer_t *hp, char *buf, int n);
int hubnet_read(hub_peer_t *hp, char *buf, int n);
int hubnet_write(hub_peer_t *hp, char *buf, int n);
int get_nonse(char *buf);


#endif
