/**
 *  Copyright (C) 2013                                                         
 *    Mika Penttilä (mika.penttila@gmail.com)                                  
 *    Pasi Patama   (ppatama@kolumbus.fi)                                      
 *  
 **/


#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "peer.h"
#include "call.h"

LIST_HEAD(peerlist);

hub_peer_t *conference_peer;
static int peers;
extern void set_max_fd(void);
extern void hub_notify(hub_peer_t *hp);

hub_peer_t *find_peer(const char *cn)
{
  struct list_head *pos;
  hub_peer_t *hp, *ret = NULL;
  
  list_for_each(pos, &peerlist) {
    hp = (hub_peer_t *)pos;
    if (!strcmp(hp->common_name, cn))
      ret = hp;
  }

  return ret;
}

hub_peer_t *find_peer_by_nonse(const char *nonse)
{
  struct list_head *pos;
  hub_peer_t *hp, *ret = NULL;
  
  list_for_each(pos, &peerlist) {
    hp = (hub_peer_t *)pos;
    if (!memcmp(hp->nonse, nonse, NONSE_LENGTH))
      ret = hp;
  }

  return ret;
}

void remove_dup_peers(const hub_peer_t *p)
{

  struct list_head *pos;
  hub_peer_t *hp, *ret = NULL;

  do {
    list_for_each(pos, &peerlist) {
      hp = (hub_peer_t *)pos;
      if (!strcmp(hp->common_name, p->common_name) &&
	  hp != p) {
	ret = hp;
	break;
      }
    }
    if (ret)
      peer_hangup(ret);
  } while (ret);
}

hub_peer_t *add_peer(int fd, peer_type_t type, const char *cn)
{

  int ret;

  hub_peer_t *hp = malloc(sizeof(hub_peer_t));
  if (!hp)
    return NULL;

  memset(hp, 0, sizeof(hub_peer_t));

  INIT_LIST_HEAD(&hp->peer_call);

  hp->control_fd = fd;
  hp->type = type;
  strcpy(hp->common_name, cn);
  
  list_add_tail(&hp->head, &peerlist);
  peers++;
  printf("audiohub: peer connect, %d peers connected\n", peers);

  return hp;
}

int remove_peer(hub_peer_t *hp)
{
  
  list_del(&hp->head);

  if (hp->fd)
    close(hp->fd);
  if (hp->control_fd)
    close(hp->control_fd);

  if (hp->pipe_from_peer[0])
    close(hp->pipe_from_peer[0]);

  if (hp->pipe_from_peer[1])
    close(hp->pipe_from_peer[1]);

  if (hp->pipe_to_peer[0])
    close(hp->pipe_to_peer[0]);

  if (hp->pipe_to_peer[1])
    close(hp->pipe_to_peer[1]);

  if (hp->mixpipe_to_peer[0])
    close(hp->mixpipe_to_peer[0]);

  if (hp->mixpipe_to_peer[1])
    close(hp->mixpipe_to_peer[1]);

  if (hp->mixpipe_from_peer[0])
    close(hp->mixpipe_from_peer[0]);

  if (hp->mixpipe_from_peer[1])
    close(hp->mixpipe_from_peer[1]);

  free(hp);
  peers--;
  printf("audiohub: peer hangup, %d peers connected\n", peers);

  return 0;
}

int peer_count(void)
{
  return peers-1; /* Don't count the conference peer */
}

void peer_hangup(hub_peer_t *hp) 
{
  reset_peer(hp);
  list_del(&hp->peer_call);
  call_hangup(hp);
  remove_peer(hp);
  set_max_fd();
  hub_notify(NULL);
}

