/*
 *  audioengine
 *  ip/opus crypto phone
 *
 *  Copyright (C) 2013 
 *    Mika Penttilä (mika.penttila@gmail.com)
 *    Pasi Patama   (ppatama@kolumbus.fi)
 *   
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
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
#include <alsa/asoundlib.h>
#include <linux/limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

char audiodevice[32];
char peer[64];
char role[16];
char capabilities[32];
char port[8];
char format[16];
char channels[8];
char rate[16];
char bits[8];
char codec[16];
char buffersize[16];
char proto[8];
char savefiledir[PATH_MAX];
char savefileduration[8];
char title3timeout[8];
int _savefileduration;
int _title3timeout;
int _saving;
char opusbitrate[8];
char opusframesize[8];
char opusendianness[8];
char opuscomp[8];
char opusexpectloss[8];
char saveropusbitrate[8];
char saveropusframesize[8];
char saveropusendianness[8];
char saveropuscomp[8];
char saveropusexpectloss[8];
char loopback[8];
int _loopback;
char llb[8];
int _llb;
char use_ssl[16];
int _use_ssl;
char hubmode[16];
int _hubmode;
int hub_peers;
char certfile[PATH_MAX];
char keyfile[PATH_MAX];
char cafile[PATH_MAX];
char infifo[PATH_MAX];
char outfifo[PATH_MAX];
char identity[32];
static char *peerlist;
static int peerlist_len;

int loopbackpipe[2];
int playerpipe[2];
int recorderpipe[2];

fd_set active_ips, active_ops;
volatile pid_t playstream_pid = -1;
volatile pid_t recordstream_pid = -1;
volatile pid_t encoder2_pid = -1;
int ctrlfifo_in, ctrlfifo_out;

typedef enum _engine_action_t {
  engine_action_none,
  engine_action_call,
  engine_action_answer,
  engine_action_hangup,
  engine_action_hello,
  engine_action_peerlist,
  engine_action_incoming_call,
  engine_action_calling,
  engine_action_established,
  engine_action_hub1,
  engine_action_hub2,
  engine_action_start_badlink,
  engine_action_stop_badlink,
} engine_action_t;

typedef enum _engine_state_t {
  engine_state_idle,
  engine_state_caller_pre_handshake,
  engine_state_callee_pre_handshake,
  engine_state_hub_connected,
  engine_state_calling,
  engine_state_ringing,
  engine_state_established,
} engine_state_t;

engine_state_t engine_state = engine_state_idle;

int streamfd = -1;
int controlfd = -1;  
int streamlistener = -1;
int saverenc_fds[2];

time_t mute_start;
int savefd = -1;
time_t save_start;

int force_sink;
char saveonly[8];
int _saveonly;

#define NONSE_LENGTH 16
static char nonse[NONSE_LENGTH];

#define INFIFO "/tmp/aefifo_in"
#define OUTFIFO "/tmp/aefifo_out"
char audioengine_reply_hello[]            = { "audioengine version 0.1 ready\n" };
char audioengine_reply_hangup[]           = { "hangup\n" };
char audioengine_reply_incoming_call[]    = { "ring ring...\n" };
char audioengine_reply_calling[]          = { "calling...\n" };
char audioengine_reply_call_established[] = { "call established\n" };
char audioengine_reply_hub1[]             = { "connected to hub\nwaiting for peer\n" };
char audioengine_reply_hub2[]             = { "connected to hub\npeer present\n" };

#define CONF_FILE_NAME "/etc/audiopipe.conf"
char conffilename[PATH_MAX] = { CONF_FILE_NAME };

#define AUDIOPIPE_PID_FILE_NAME "/tmp/audiopipe.pid"
#define CHUNK_SIZE 4096

#define FIFO_MAXARGS 256
char fifoargs[FIFO_MAXARGS];

extern int net_control_read(int fd, char *buf, int n);
extern int send_identity(int fd, char *identity);
extern int send_nonse(int fd, char *buf, int n);
extern int hub_make_call(int fd, char *fifoargs);
extern int ssl_init(int caller, int fd, int iscontrol);
extern char *net_get_caller_id(void);
extern char *net_get_cipher(void);
extern void net_hangup(void);
extern int run_established(fd_set *ips, fd_set *ops, int streamfd, int inpipe, int outpipe);
extern int create_stream_listener_sock(void);
extern int create_stream_sock(char *_role, int control);

int send_guid(int streamfd);
int receive_guid(int streamfd);
int send_answer(int streamfd);
int receive_answer(int streamfd);
void fifo_command_send_reply(engine_action_t action);

//static pid_t fork_encoder(int fd_in, int fd_out, int issaver);
static void do_hangup(void);
static void accept_stream(void);
static void launch_stream(void);
static void answer_call(void);

int opusenc(const char *audiodevice, char *_format, unsigned int _buffersize, unsigned int _bits, unsigned int _channels, unsigned int _rate, unsigned int _endianness, unsigned int _bitrate, char *_framesize, unsigned int _comp, int to, int dummy);
int opusdec(const char *audiodevice, char *_format, unsigned int _buffersize, unsigned int _bits, unsigned int _channels, int _rate, int from, int dummy);
/* dummy to satisfy linking */
void bridge_write(int writer, unsigned char *data, int len) {};

/* Title3 support */
static int should_mute(void) 
{

  if (mute_start) {
    time_t now = time(NULL);
    if (now - mute_start < _title3timeout) 
      return 1;
    
    mute_start = 0;    
  }
  
  return 0;
}

static void create_save_file(void)
{
  char tmp[PATH_MAX];
  char datestr[32];

  mkdir(savefiledir, S_IRUSR|S_IWUSR |S_IXUSR);
  strcpy(tmp, savefiledir);
  strcat(tmp, "/");

  time_t now = time(NULL);

  struct tm *tm = gmtime(&now);
  sprintf(datestr, "%d%02d%02d%02d%02d%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

  strcat(tmp, datestr);
  strcat(tmp, ".opus");
  savefd = open(tmp, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
  if (savefd < 0)
    perror("could not create file for stream saving.");
  save_start = now;
}

static void close_save_file(void)
{
  close(savefd);
  savefd = -1;
}

static void write_save_file(const char *ptr, int n)
{
  time_t now;

  pid_t tmp;

  if (savefd < 0)
    create_save_file();
    
  if (savefd < 0)
    return;

  now = time(NULL);
  
  if (now - save_start > _savefileduration) {
    close_save_file();

    if ((tmp=encoder2_pid) > 0) {
      kill(tmp, SIGKILL);
      waitpid(tmp, NULL, 0); 
      encoder2_pid = -1; //fork_encoder(saverenc_fds[0], saverenc_fds[1], 1);
    }
  }
  write(savefd, ptr, n);
}

static void report_pid(void) 
{
  int ret;
  pid_t mypid = getpid();
  char buf[16];
  
  sprintf(buf, "%d\n", mypid);
  int fd = open(AUDIOPIPE_PID_FILE_NAME, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
  ret = write(fd, buf, strlen(buf));
  close(fd);
}

#if 0
static char httpline[]="HTTP/1.1 200 OK\r\n";
static char contenttypeline[]="Content-Type: audio/ogg\r\n\r\n";

static void write_http_headers(int fd) 
{
  send(fd, httpline, strlen(httpline), MSG_NOSIGNAL);
  send(fd, contenttypeline, strlen(contenttypeline), MSG_NOSIGNAL);

}
#endif
static void audio_source(int upstream_fd)
{
    if (!strcmp(codec, "opus")) 
      opusenc(audiodevice, format, atoi(buffersize), atoi(bits), atoi(channels), atoi(rate), atoi(opusendianness), atoi(opusbitrate), opusframesize, atoi(opuscomp), upstream_fd, -1);
    
    exit(0);
}

static void audio_sink(int upstream_fd)
{

    if (!strcmp(codec, "opus")) 
      opusdec(audiodevice, format, atoi(buffersize), atoi(bits), atoi(channels), atoi(rate), upstream_fd, -1);     
    exit(0);
}

static int parse_conf_opt(char *buf, char *option, char *value) 
{
  char *ptr, *ptr2, *tmp;
  int n;
  char fmt[256];

  strcpy(fmt, option);
  strcat(fmt, " = %s");

  char *line = strtok((tmp=strdup(buf)), "\n");
  while (line) {

    ptr  = strstr(line, option);
    ptr2 = strstr(line, "#");

    if (ptr && ptr2 && ptr2 < ptr) 
      goto next_line;
    
    if (ptr) {      
      n = sscanf(ptr, fmt, value);
      if (n == 1) {
	free(tmp);
	return 1;
      }
    }
  next_line: 
    line  = strtok(NULL, "\n");
  }
  
  free(tmp);
  return 0;
}

struct conf_opt {
  char *name;
  char *value;
  char *def;
};

static struct conf_opt conf_opts[] = {
  { "device", audiodevice, "default" },
  { "role", role, "" },
  { "capabilities", capabilities, "" },
  { "peer", peer, "" },
  { "port", port, "5858" },
  { "proto", proto, "tcp" },
  { "format", format, "S16_BE" },
  { "channels", channels, "2" },
  { "rate", rate, "48000" },
  { "codec", codec, "opus" },
  { "buffersize", buffersize, "65536" },
  { "savefiledir", savefiledir, "" },
  { "savefileduration", savefileduration, "1800" },
  { "title3timeout", title3timeout, "30" },
  { "saveonly", saveonly, "false" },
  { "opusbitrate", opusbitrate, "16" },
  { "opusframesize", opusframesize, "20" },
  { "opusendianness", opusendianness, "1" },
  { "opuscomp", opuscomp, "1" },
  { "opusexpectloss", opusexpectloss, "0" },
  { "saveropusbitrate", saveropusbitrate, "16" },
  { "saveropusframesize", saveropusframesize, "20" },
  { "saveropusendianness", saveropusendianness, "1" },
  { "saveropuscomp", saveropuscomp, "1" },
  { "saveropusexpectloss", saveropusexpectloss, "0" },
  { "loopback", loopback, "false" },
  { "llb", llb, "false" },
  { "ssl", use_ssl, "false" },
  { "certfile", certfile, "" },
  { "keyfile", keyfile, "" },
  { "cafile", cafile, "" },
  { "hubmode", hubmode, "false" },
  { "identity", identity, "" },
  { "infifo", infifo, "/tmp/aefifo_in" },
  { "outfifo", outfifo, "/tmp/aefifo_out" },

};

static void parse_conf(void)
{
  size_t i;
  int ret;
  int fd = open(conffilename, O_RDONLY);
  if (fd < 0)
    return;

  off_t length = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  char *buf = malloc(length+1);
  if (!buf) {
    close(fd);
    return;
  }

  buf[length] = 0;
  ret = read(fd, buf, length);
  close(fd);

  for (i=0; i < (sizeof(conf_opts) / sizeof (conf_opts[0])); i++) {
    strcpy(conf_opts[i].value, conf_opts[i].def);
    parse_conf_opt(buf, conf_opts[i].name, conf_opts[i].value);
    printf("%s = %s\n", conf_opts[i].name, conf_opts[i].value);

  }

  _savefileduration = atoi(savefileduration);
  _title3timeout = atoi(title3timeout);
  _saveonly = !strcmp(saveonly, "true");

  if (strstr(format, "BE")) {
    strcpy(opusendianness, "1");
    strcpy(saveropusendianness, "1");
  }
  else { 
    strcpy(opusendianness, "0");
    strcpy(saveropusendianness, "0");
  }

  if (strstr(format, "16"))
    strcpy(bits, "16");
  else
    strcpy(bits, "8");
  printf("bits = %s\n", bits);  

  if (strlen(savefiledir)) 
    _saving = 1;
  else
    _saving = 0;

  if (!_saving)
    _saveonly = 0;

  _loopback = !(strcmp(loopback, "true"));
  _llb = !(strcmp(llb, "true"));

  _use_ssl = !strcmp(use_ssl, "true");
  _hubmode = !strcmp(hubmode, "true");

  // TODO compatible with old behaviour
  if (!strlen(role)) {
    printf("audioengine: backward compatiblity :\n");
    if (force_sink || !strlen(peer)) {
      strcpy(role, "target");
      strcpy(capabilities, "play");
      printf(" assuming role='target' and capabilites='play'\n");
    }
    else {
      strcpy(role, "initiator");
      strcpy(capabilities, "record");
      printf(" assuming role='initiator' and capabilites='record'\n");
    }
  }

  free(buf);  
}


static void sigchld_hdl(int sig)
{

  pid_t pid;

  while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
    
    if (pid == playstream_pid) {
      printf("...caught player subsystem death signal\n");
      playstream_pid = -1;
    }
    if (pid == recordstream_pid) {
      printf("...caught recorder subsystem  death signal\n");
      recordstream_pid = -1;
    }
  }
}

static void sigusr1_hdl (int sig)
{
    fifo_command_send_reply(engine_action_start_badlink);
}

static void sigusr2_hdl (int sig)
{
    fifo_command_send_reply(engine_action_stop_badlink);
}

static void sigpipe_hdl (int sig)
{
}

static void sigint_hdl (int sig)
{
  do_hangup();
  exit(0);
}
 
static void parse_args(int argc, char **argv)
{

  int i;

  for(i=1; i < argc; i++) {
    if(!strcmp(argv[i], "--sink"))
      force_sink = 1;

    if (!strcmp(argv[i], "-f") && i+1 < argc)
      strcpy(conffilename, argv[i+1]);
  }
}

static void setup_signals(void)
{
  struct sigaction act;   
  memset (&act, 0, sizeof(act));
  act.sa_handler = sigchld_hdl;
  act.sa_flags = SA_RESTART;
  
  if (sigaction(SIGCHLD, &act, 0)) {
    perror ("sigaction - SIGCHLD");
    exit(1);
  }

  memset (&act, 0, sizeof(act));
  act.sa_handler = sigint_hdl;
  act.sa_flags = SA_RESTART;
  
  if (sigaction(SIGINT, &act, 0)) {
    perror ("sigaction - SIGINT");
    exit(1);
  }

  memset (&act, 0, sizeof(act));
  act.sa_handler = sigpipe_hdl;
  
  if (sigaction(SIGPIPE, &act, 0)) {
    perror ("sigaction - SIGPIPE");
    exit(1);
  }

  memset (&act, 0, sizeof(act));
  act.sa_handler = sigusr1_hdl;
  act.sa_flags = SA_RESTART;
  sigaddset(&act.sa_mask, SIGUSR2);
  
  if (sigaction(SIGUSR1, &act, 0)) {
    perror ("sigaction - SIGUSR1");
    exit(1);
  }

  memset (&act, 0, sizeof(act));
  act.sa_handler = sigusr2_hdl;
  act.sa_flags = SA_RESTART;
  sigaddset(&act.sa_mask, SIGUSR1);
  
  if (sigaction(SIGUSR2, &act, 0)) {
    perror ("sigaction - SIGUSR2");
    exit(1);
  }

}

static void fork_player_subsystem(int fd) 
{

  playstream_pid = fork();

  if (playstream_pid < 0)
    error(1, errno, "Could not fork playstream");
          
  if (playstream_pid)
    return;

  setup_signals();
  audio_sink(fd);
  exit(0);

}

static void  fork_recorder_subsystem(int fd) 
{
  recordstream_pid = fork();

  if (recordstream_pid < 0)
    error(1, errno, "Could not fork recordstream");
          
  if (recordstream_pid)
    return;

  setup_signals();
  audio_source(fd);
  exit(0);
}

void write_fifo_status_command(char *ptr, int len)
{
  char *tmp;
  int ret;

  tmp = malloc(len+3);
  if (tmp) {
    tmp[0] = 'S';
    tmp[1] = len >> 8;
    tmp[2] = len & 0xff;
    memcpy(tmp+3, ptr, len);
    ret = write(ctrlfifo_out, tmp, len+3);
    free(tmp);
  }
    
}
void fifo_command_send_reply(engine_action_t action)
{

  int ret;
  char tmp[256];
  char *ptr = NULL;
  switch (action) {

  case engine_action_hangup:
    write_fifo_status_command(audioengine_reply_hangup, strlen(audioengine_reply_hangup));
    break;
  case engine_action_established:
    if (!_use_ssl)
      write_fifo_status_command(audioengine_reply_call_established, strlen(audioengine_reply_call_established));
    else {
      strcpy(tmp, "Call established with\n");
      strcat(tmp, net_get_caller_id());
      strcat(tmp, "\ncipher: ");
      strcat(tmp, net_get_cipher());
      strcat(tmp, "\n");
      write_fifo_status_command(tmp, strlen(tmp));

    }
    break;

  case engine_action_hello:
    strcpy(tmp, audioengine_reply_hello);
    write_fifo_status_command(audioengine_reply_hello, strlen(audioengine_reply_hello));

    if (!_hubmode || engine_state != engine_state_hub_connected)
      break;
    /* fallthrough */
  case engine_action_peerlist:
   ptr = malloc(peerlist_len+3);
   if (ptr) {     
     memcpy(ptr+3, peerlist, peerlist_len);
     ptr[0] = 'L';
     ptr[1] = peerlist_len >> 8;
     ptr[2] = peerlist_len & 0xff;   
     ret = write(ctrlfifo_out, ptr, peerlist_len+3);    
     free(ptr);
   }
   break;

  case engine_action_start_badlink:
   ptr = malloc(3+1);
   if (ptr) {     
     ptr[0] = 'W';
     ptr[1] = 0;
     ptr[2] = 1;

     ptr[3] = 1;
     ret = write(ctrlfifo_out, ptr, 3+1);    
     free(ptr);
   }
   break;

  case engine_action_stop_badlink:
   ptr = malloc(3+1);
   if (ptr) {     
     ptr[0] = 'W';
     ptr[1] = 0;
     ptr[2] = 1;

     ptr[3] = 0;
     ret = write(ctrlfifo_out, ptr, 3+1);
     free(ptr);
   }
   break;

  case engine_action_incoming_call:
    if (_hubmode) {
      strcpy(tmp, fifoargs);
      strcat(tmp, "\nis calling...\n");
      write_fifo_status_command(tmp, strlen(tmp));
    } else {
      if (!_use_ssl)
	write_fifo_status_command(audioengine_reply_incoming_call, strlen(audioengine_reply_incoming_call));    
      else {
	strcpy(tmp, net_get_caller_id());
	strcat(tmp, "\nis calling...\ncipher: ");
	strcat(tmp, net_get_cipher());
	strcat(tmp, "\n");
	write_fifo_status_command(tmp, strlen(tmp));
      }
    }
    break;

  case engine_action_calling:
    if (_hubmode) {
       strcpy(tmp, "calling\n");
       strcat(tmp, fifoargs);
       strcat(tmp, "\n");
      write_fifo_status_command(tmp, strlen(tmp));
    } else {
      if (!_use_ssl) 
	write_fifo_status_command(audioengine_reply_calling, strlen(audioengine_reply_calling));    
      else {	
	strcpy(tmp, "calling\n");
	strcat(tmp, net_get_caller_id());
	strcat(tmp, " ...\ncipher: ");
	strcat(tmp, net_get_cipher());
	strcat(tmp, "\n");
	write_fifo_status_command(tmp, strlen(tmp));
      }
    }
    break;
  }
}

engine_action_t fifo_parse_call(char *buf, int n)
{
  int tmp;
  memset(fifoargs, 0, FIFO_MAXARGS);
  /*  "C somename"  */
  if (n >= 3) {
    tmp = n-2;
    if (tmp >= FIFO_MAXARGS)
      tmp = FIFO_MAXARGS -1;
    memcpy(fifoargs, buf+2, tmp);
    printf("calling %s\n", fifoargs);
  }
  return engine_action_call;
}

engine_action_t fifo_command(int fd_in, int fd_out) 
{

  int ret;
  char buf[128];
  ret = read(fd_in, buf, 128);
  if (ret <= 0) {
    printf("no action\n");
    return engine_action_none;
  }

  switch(buf[0]) {
  case 'H':
    return engine_action_hangup;
  case 'C':
    return fifo_parse_call(buf, ret);
  case 'A':
    return engine_action_answer;
  case '!':
    return engine_action_hello;

  }
  
  return engine_action_none;
}

static int create_control_fifos(void)
{

  mknod(infifo, S_IFIFO | S_IRWXU, 0);
  mknod(outfifo, S_IFIFO | S_IRWXU, 0);

  ctrlfifo_in = open(infifo, O_RDWR);
  if (ctrlfifo_in < 0) {
    perror("couldn't open control pipe.");
    return -1;
  }

  ctrlfifo_out = open(outfifo, O_RDWR);
  if (ctrlfifo_out < 0) {
    perror("couldn't open control pipe.");
    return -1;
  }
  fcntl(ctrlfifo_in, F_SETFL, O_NONBLOCK);
  fcntl(ctrlfifo_out, F_SETFL, O_NONBLOCK);

  return 0;
}

static void initiate_handshake(void)
{
  if (!_hubmode)
    FD_CLR(streamlistener, &active_ips);

  if (!_hubmode)
    fcntl(streamfd, F_SETFL, O_NONBLOCK);
  FD_SET(streamfd, &active_ips);
  FD_SET(streamfd, &active_ops);
  if (send_guid(streamfd) < 0) 
    do_hangup();
    
}

static void finish_handshake(void)
{
  int ret;
  if ((ret = receive_guid(streamfd)) < 0) {
    do_hangup();
    return;
  }
  if (!ret)
    return;

  if (engine_state == engine_state_caller_pre_handshake) {
    engine_state = engine_state_calling;
    fifo_command_send_reply(engine_action_calling);
  }

  if (engine_state == engine_state_callee_pre_handshake) {
    engine_state = engine_state_ringing;
    fifo_command_send_reply(engine_action_incoming_call);
    if (_loopback)
      answer_call();
  }

}

static void make_call(void)
{

  if (_hubmode && engine_state == engine_state_idle)
    return;

  if (engine_state == engine_state_idle || engine_state == engine_state_hub_connected) {
    if (!_hubmode) {
      streamfd = create_stream_sock("initiator", 0);
      if (streamfd < 0) {
	perror("connect() failed");
	do_hangup();
	return;      
      }
    } else {
      if (hub_make_call(controlfd, fifoargs) < 0) {
	do_hangup();
	return;
      }
    }
    engine_state = engine_state_caller_pre_handshake;
    if (ssl_init(1, streamfd, 0) < 0) {
      do_hangup();
      return;
    }
    initiate_handshake();
    return;
  }
  answer_call();
  
}

static void hub_connect(void)
{

  controlfd = create_stream_sock("initiator", 1);
  if (controlfd < 0)
    return;

  if (ssl_init(1, controlfd, 1) < 0) {
    do_hangup();
    return;
  }
  FD_SET(controlfd, &active_ips);
  if (send_identity(controlfd, identity) < 0) {
    do_hangup();
    return;
  }

  if (net_control_read(controlfd, nonse, NONSE_LENGTH) < 0) {
    do_hangup();
    return;
  }

  streamfd = create_stream_sock("initiator", 0);
  if (streamfd >= 0) {
    if (send_nonse(streamfd, nonse, NONSE_LENGTH) < 0) {
      do_hangup();
      return;
    }
    FD_SET(streamfd, &active_ips);
    engine_state = engine_state_hub_connected;
  } 
  else
    do_hangup();
}

static void accept_stream(void) 
{
  
  int flag = 1;
  int sendbuff=4096;
  int rcvbuff=4096;
  int clamp = 2048;
  
  if (!_hubmode) {
    streamfd = accept(streamlistener, (struct sockaddr*)NULL, NULL); 
    if (streamfd < 0) {
      perror("accept() failed");
      do_hangup();
      return;
    }
#if 1
    setsockopt(streamfd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
    setsockopt(streamfd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));
    //setsockopt(streamfd, SOL_SOCKET, TCP_WINDOW_CLAMP, (char *)& clamp, sizeof(clamp));
#endif
    
    setsockopt(streamfd,          
	       IPPROTO_TCP,     
	       TCP_NODELAY,     
	       (char *) &flag,               
	       sizeof(int));    
  }
    
  engine_state = engine_state_callee_pre_handshake;
  if (ssl_init(0, streamfd, 0) < 0) {
    do_hangup();
    return;
  }
  initiate_handshake();
  
}

static void answer_call(void)
{
  if (engine_state == engine_state_ringing) {
    send_answer(streamfd);
    launch_stream();
  }
}

static void call_answered(void)
{
  int ret;
  if ((ret = receive_answer(streamfd)) < 0) {
    do_hangup();
    return;
  }

  if (!ret)
    return;

  launch_stream();
}

static void kill_subprocesses(void) 
{
  pid_t tmp;
  if ((tmp=playstream_pid) > 0) {
    kill(tmp, SIGKILL);
    waitpid(tmp, NULL, 0);
    playstream_pid = -1;
  }
  
  if ((tmp=recordstream_pid) > 0) {
    kill(tmp, SIGKILL);
    waitpid(tmp, NULL, 0);
    recordstream_pid = -1;
  }

}

static void do_hangup(void)
{
  net_hangup();
  kill_subprocesses();
  if (streamfd >= 0) {
    FD_CLR(streamfd, &active_ips);
    FD_CLR(streamfd, &active_ops);
    shutdown(streamfd, SHUT_RDWR);
    close(streamfd);
    streamfd = -1;
  }
  if (controlfd >= 0) {
    FD_CLR(controlfd, &active_ips);
    shutdown(controlfd, SHUT_RDWR);
    close(controlfd);
    controlfd = -1;
  }
    
  if (playerpipe[0] >= 0) {
    close(playerpipe[0]);
    playerpipe[0] = -1;
  }
  if (playerpipe[1] >= 0) {
    FD_CLR(playerpipe[1], &active_ops);
    close(playerpipe[1]);
    playerpipe[1]  = -1;
  }
  if (recorderpipe[0] >= 0) {
    FD_CLR(recorderpipe[0], &active_ips);
    close(recorderpipe[0]);
    recorderpipe[0] = -1;
  }
  if (recorderpipe[1] >= 0) {
    close(recorderpipe[1]);
    recorderpipe[1] = -1;
  }
  
  if (!_hubmode)
    FD_SET(streamlistener, &active_ips);
  
  engine_state = engine_state_idle;
  fifo_command_send_reply(engine_action_hangup);
  fifo_command_send_reply(engine_action_stop_badlink);
}

static void do_hello(void)
{
  char buf[4096];
  while (1) {
    if (read(ctrlfifo_out, buf, 4096) < 0)
      if (errno == EAGAIN)
	break;
  }
  fifo_command_send_reply(engine_action_hello);

}

static void engine_action(void)
{
  engine_action_t action;
  action = fifo_command(ctrlfifo_in, ctrlfifo_out);
  switch (action) {
  case engine_action_none:
    break;
  case engine_action_call:
    make_call();
    break;
  case engine_action_answer:
    answer_call();
    break;
  case engine_action_hangup:
    do_hangup();
    break;
 case engine_action_hello:
   do_hello();
   break;
  }
}

static int get_maxfd(void) 
{
  int tmp = streamlistener;

  if (ctrlfifo_in > tmp)
    tmp = ctrlfifo_in;

  if (playerpipe[1] > tmp)
    tmp = playerpipe[1];

  if (recorderpipe[0] > tmp)
    tmp = recorderpipe[0];

  if (streamfd > tmp)
    tmp = streamfd;

  if (controlfd > tmp)
    tmp = controlfd;

  return tmp;
}

static void launch_stream(void)
{

  int mode;
  int ret;
  ret = pipe(playerpipe);
  ret = pipe(recorderpipe);

  fcntl(playerpipe[1], F_SETFL, O_NONBLOCK);
  fcntl(recorderpipe[0], F_SETFL, O_NONBLOCK);
 
  if (!_llb) {
    mode = fcntl(streamfd, F_GETFL, 0);
    fcntl(streamfd, F_SETFL, mode & ~O_NONBLOCK);
  }

  FD_SET(playerpipe[1], &active_ops);
  FD_SET(recorderpipe[0], &active_ips);

  engine_state = engine_state_established;
  fork_player_subsystem(playerpipe[0]);
  sleep(1);
  fork_recorder_subsystem(recorderpipe[1]);
  if (!_llb)
    fifo_command_send_reply(engine_action_established);

}

static void process_peer_list(char *ptr, size_t len)
{
  size_t tmp;
  unsigned char status;
  printf("peer list :\n");
  peerlist_len = len;
  peerlist = realloc(peerlist, len);
  memcpy(peerlist, ptr, len);
  while (len > 0) {

    tmp = strlen(ptr);
    status = *(ptr + tmp + 1);
    printf("%s - status %s\n", ptr, status ? "busy" : "available");
    ptr += (tmp + 2);
    len -= (tmp + 2);
  }
 
}

static void hub_io(void)
{
  unsigned char buf[3];
  size_t  n, len, tmp;
  char *ptr;
  int ret;

  printf("hub io\n");
  n = net_control_read(controlfd, buf, 3);
  if (n <= 0) {
    do_hangup();
    return;
  }
  
  if (n < 3) 
    return;
  
  len = buf[1] * 256 + buf[2];
  ptr = malloc(len);
  
  n = net_control_read(controlfd, ptr, len);
  if (n <= 0) {
    free(ptr);
    do_hangup();
    return;
  }

  if (n < len) { 
    free(ptr);
    return;
  }

  switch (buf[0]) {
  case 'L':
    process_peer_list(ptr, len);
    fifo_command_send_reply(engine_action_peerlist);
    break;

  case 'C':
    memset(fifoargs, 0, sizeof(fifoargs));
    tmp = len;
    if (tmp >= FIFO_MAXARGS)
      tmp = FIFO_MAXARGS -1;
    memcpy(fifoargs, ptr, tmp);
    printf("incoming call\n");
    accept_stream();
    
  }  

  free(ptr);
}

static void audioengine(void) 
{

  fd_set ips, ops;
  int ret;

  struct timeval timeout;
  FD_ZERO(&active_ips);
  FD_ZERO(&active_ops);

  if (create_control_fifos() < 0)
    goto error_out;

  if (!_hubmode && !_llb) {
    streamlistener = create_stream_listener_sock();
    FD_SET(streamlistener, &active_ips);
  }
  FD_SET(ctrlfifo_in, &active_ips);

  if (_loopback)
    ret = pipe(loopbackpipe);

  if (_llb) {
    printf("starting llb\n");
    launch_stream();
  }

  while(1) {

    memcpy(&ips, &active_ips, sizeof(fd_set));
    memcpy(&ops, &active_ops, sizeof(fd_set));
       
  
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
     
    if ((ret = select(get_maxfd()+1, &ips, &ops, NULL, &timeout)) < 0) {
      perror("select() failed");
      do_hangup();
      continue;
    }

    if (_llb) {
      /* local loopback */
      run_established(&ips, &ops, -1, recorderpipe[0], playerpipe[1]);
      continue;
    }
    if (ret == 0) {
      if (_hubmode && (engine_state == engine_state_idle)) 
	hub_connect();
      continue;
    }
    
    if (FD_ISSET(ctrlfifo_in, &ips)) {
      engine_action();
      continue;
    }

    if (engine_state == engine_state_established) {
      ret = run_established(&ips, &ops, streamfd, recorderpipe[0], playerpipe[1]);
      if (ret < 0) {
	do_hangup();
	continue;
      }	
    }

    if (((engine_state == engine_state_caller_pre_handshake) ||
	 (engine_state == engine_state_callee_pre_handshake)) &&
	FD_ISSET(streamfd, &ips)) {
      finish_handshake();
      continue;
    }
    
    if (engine_state == engine_state_ringing && FD_ISSET(streamfd, &ips))
      /* just receive anything to detect hangup */
      if (receive_guid(streamfd) < 0) {
	do_hangup();
	continue;
      }
    
    if (engine_state == engine_state_calling && FD_ISSET(streamfd, &ips)) {
      call_answered();
      continue;
    }

    if (_hubmode && FD_ISSET(controlfd, &ips)) {
      hub_io();
    }

    if (!_hubmode && engine_state == engine_state_idle && FD_ISSET(streamlistener, &ips)) {
      printf("incoming call\n");
      accept_stream();
    }
  }

  if (streamfd >= 0)
    close(streamfd);

  if (!_hubmode)
    close(streamlistener);

  if (_loopback) {
    close(loopbackpipe[0]);
    close(loopbackpipe[1]);
  }
 error_out:
  do_hangup();
  
}

int main(int argc, char **argv)
{
  
  parse_args(argc, argv);
  setup_signals();
  report_pid();

  while (1) {
    parse_conf();  
    printf("audioengine: starting.\n");
    audioengine();
    printf("audioengine: exiting.\n");
    sleep(1);
  }
  return 0;
}
