#ifndef _CALL_H_
#define _CALL_H_

#include "list.h"


typedef enum _call_type_t {
  call_normal,
  call_conference,
} call_type_t;

typedef struct _call_t {
  struct list_head head;
  struct list_head peers;
  call_type_t type;
} call_t;

#include "peer.h"

extern call_t *conference_call;
extern struct list_head call_list;

hub_peer_t *call_peer_name(hub_peer_t *hp, const char *name);
void call_hangup(hub_peer_t *hp);
int create_conf_call(void);
int call_peer_count(call_t *call);
#endif
