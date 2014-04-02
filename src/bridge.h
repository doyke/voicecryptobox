#ifndef _BRIDGE_H_
#define _BRIDGE_H_

int bridge_initialize(void);
int bridge_allocate_channel(void);
const char *bridge_channel_devicename(int i);
void bridge_free_channel(int channel);
void bridge_write(int writer, unsigned char *data, int len);

#endif
