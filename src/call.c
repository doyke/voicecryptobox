/**
 *
 *
 *  Copyright (C) 2013                                                         
 *    Mika Penttilä (mika.penttila@gmail.com)                                  
 *    Pasi Patama   (ppatama@kolumbus.fi)                                      
 *  
 **/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "call.h"
#include "peer.h"

LIST_HEAD(call_list);

call_t *conference_call;

call_t *new_call(hub_peer_t *peer1, hub_peer_t *peer2)
{

  int ret;

  call_t *c = malloc(sizeof(call_t));
  if (!c)
    return NULL;

  memset(c, 0, sizeof(call_t));

  INIT_LIST_HEAD(&c->peers);  
  c->type = call_normal;
  list_add_tail(&c->head, &call_list);
  list_add_tail(&peer1->peer_call, &c->peers);
  list_add_tail(&peer2->peer_call, &c->peers);

  peer1->active_call = peer2->active_call = c;
  peer1->status = peer_status_busy;
  peer2->status = peer_status_busy;

  return c;
}

int call_peer_count(call_t *c)
{

  struct list_head *pos;

  int n = 0;
  
  list_for_each(pos, &c->peers) {
    n++;
  }

  return n;
}

/*
 * peer1 is calling peer2,
 * peer2 may be a conference call
 */

static int call_peer(hub_peer_t *peer1, hub_peer_t *peer2)
{

  if (peer2->type == peer_normal) {
    /* See if either is busy */
    if (!list_empty(&peer1->peer_call) || !list_empty(&peer2->peer_call))
      return -1;
    new_call(peer1, peer2);
  } else {
    if (!list_empty(&peer1->peer_call))
      return -1;
    /* Add peer1 to conference */
    //list_add(&peer1->peer_call, &peer2->peer_call);
    list_add_tail(&peer1->peer_call, &conference_call->peers);
    peer1->active_call = conference_call;
  }
  return 0;
}
    
hub_peer_t *call_peer_name(hub_peer_t *hp, const char *name)
{
  hub_peer_t *other = find_peer(name);
  
  if (!other)
    return NULL;

  if  (call_peer(hp, other) == 0)
    return other;
  else
    return NULL;
}

int create_conf_call(void)
{
  int ret;

  conference_peer = add_peer(0, peer_conference, "conference");

  call_t *c = malloc(sizeof(call_t));
  if (!c)
    return -1;

  memset(c, 0, sizeof(call_t));
  
  c->type = call_conference;
  INIT_LIST_HEAD(&c->peers);

  //list_add_tail(&c->head, &call_list);
  conference_call = c;
  conference_peer->active_call = conference_call;

  return 0;
}

static void remove_call(call_t *c)
{

  list_del(&c->head);
  free(c);
}

void call_hangup(hub_peer_t *hp)
{
  hub_peer_t *hp1, *hp2;

  call_t *call = hp->active_call;
  if (!call || call == conference_call) {
    hp->active_call = NULL;
    return;
  }

  /**
     If this peer has an active call there must be at least
     one other peer
  */
  hp1 = list_first_entry(&call->peers, hub_peer_t, peer_call);
  hp2 = list_first_entry(&hp1->peer_call, hub_peer_t, peer_call);

  if (hp1 != hp) {
    hp1->active_call = NULL;
    peer_hangup(hp1);
  }
  else {
    hp2->active_call = NULL;
    peer_hangup(hp2);
  }
      
  remove_call(call);
}
