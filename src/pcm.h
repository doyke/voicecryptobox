#ifndef _PCM_H_
#define _PCM_H_


int write_to_pcm(char *ptr, int n);
int read_from_pcm(char *ptr, int n);
int open_pcm(const char *audiodevice, int record, unsigned int rate, char *format, unsigned int buffersize, unsigned int channels, unsigned int bits, int bridge_pipe);
void close_pcm(void);
#endif
