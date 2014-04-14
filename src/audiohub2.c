/**
 *  audihub
 *  ip phone conferencing / p2p hub
 *
 *  Copyright (C) 2013                                                          *
 *    Mika Penttilä (mika.penttila@gmail.com)                                  
 *    Pasi Patama   (ppatama@kolumbus.fi)                                       *
 *  
 *   
 **/

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <error.h>
#include <linux/limits.h>

#include "peer.h"
#include "call.h"
#include "hubnet.h"

#define NETBUF_SIZE 4096
static char buf[NETBUF_SIZE];
#define SAMPLE_VALUE_MAX  32767
#define SAMPLE_VALUE_MIN -32768

char certfile[PATH_MAX];
char keyfile[PATH_MAX];
char cafile[PATH_MAX];

#define CONF_FILE_NAME "/etc/audiohub.conf"
char conffilename[PATH_MAX] = { CONF_FILE_NAME };
static char hubport[8];
static char use_ssl[8];

fd_set active_ips, active_ops;
fd_set ips, ops;
int listener         = -1;
int control_listener = -1;
int _hubport;
int maxfd            = -1;
int _use_ssl         =  0;

/* Dummy for now just to satisfy linking pcm.o */
int loopbackpipe[2];
int _loopback;
static int initiate_handshake(hub_peer_t *hp);
int opusenc(const char *audiodevice, char *_format, unsigned int _buffersize, unsigned int _bits, unsigned int _channels, unsigned int _rate, unsigned int _endianness, unsigned int _bitrate, char *_framesize, unsigned int _comp, int to, int _pipe);

int opusdec(const char *audiodevice, char *_format, unsigned int _buffersize, unsigned int _bits, unsigned int _channels, int _rate, int from, int _pipe);

int timer_active;

static int maybe_start_timer(hub_peer_t *hp);
static int maybe_stop_timer(hub_peer_t *hp);

static int timeval_subtract (struct timeval *result, 
			     struct timeval *x, struct timeval  *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

static int create_listener_sock(int control)
{
  int ret, listenfd;
  struct sockaddr_in servaddr;

  bzero(&servaddr,sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = control ? htons(_hubport - 1) : htons(_hubport);
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

void hub_notify(hub_peer_t *exclude)
{
  struct list_head *pos, *pos2;
  hub_peer_t *hp, *hp2;
  unsigned char *ptr;
  size_t datasize;
  size_t tmp;
  size_t tmp2;
  
  list_for_each(pos, &peerlist) {
    hp = (hub_peer_t *)pos;

    if (hp == exclude)
      continue;
    if (hp == conference_peer)
      continue;

    datasize = 3; /* command + len */
    ptr = malloc(datasize);
    ptr[0] = 'L';
    list_for_each(pos2, &peerlist) {
      tmp = datasize;
      hp2 = (hub_peer_t *)pos2;
      tmp2 = strlen(hp2->common_name);
      datasize += tmp2 + 2; /* name + '0' + status */
      ptr = realloc(ptr, datasize);    
      strcpy(ptr + tmp, hp2->common_name);
      ptr[tmp + tmp2] = 0;
      ptr[tmp + tmp2 + 1] = hp2->status;
    }
    tmp = (datasize-3) & 0xffff;
    ptr[1] = tmp >> 8;
    ptr[2] = tmp & 0xff;
    hubnet_ctrl_write(hp, ptr, datasize);
    free(ptr);
  }    
}

void set_max_fd(void) 
{

  struct list_head *pos;
  hub_peer_t *hp;
  int n;
  
  maxfd = listener;
  if (control_listener > maxfd)
    maxfd = control_listener;

  list_for_each(pos, &peerlist) {
    hp = (hub_peer_t *)pos;

    if (hp == conference_peer)
      continue;

    if (hp->control_fd > maxfd) 
      maxfd = hp->control_fd;
    if (hp->fd > maxfd) 
      maxfd = hp->fd;
    if (hp->pipe_to_peer[0] > maxfd)
      maxfd = hp->pipe_to_peer[0];
    
    if (hp->pipe_from_peer[1] > maxfd)
      maxfd = hp->pipe_from_peer[1];

    if (hp->mixpipe_from_peer[0] > maxfd)
      maxfd = hp->mixpipe_from_peer[0];

    if (hp->mixpipe_to_peer[1] > maxfd)
      maxfd = hp->mixpipe_to_peer[1];
    
  }
}

static void default_signals(void) 
{

  struct sigaction act;
  memset (&act, 0, sizeof(act));
  act.sa_handler = SIG_DFL;
  sigaction(SIGALRM, &act, 0);
}

static void fork_decoder(hub_peer_t *hp)
{

  hp->decoder = fork();

  if (hp->decoder < 0)
    error(1, errno, "Could not fork decoder process.");

  if (hp->decoder)
    return;

  default_signals();
  opusdec("", "S16_LE", 32768, 16, 1, 48000, hp->pipe_from_peer[0], hp->mixpipe_from_peer[1]);

  exit(0);
}

static void fork_encoder(hub_peer_t *hp)
{
  const char *audiodevice;
  hp->encoder = fork();

  if (hp->encoder < 0)
    error(1, errno, "Could not fork encoder process.");

  if (hp->encoder)
    return;

  default_signals();
  opusenc("", "S16_LE", 32768, 16, 1, 48000, 0, 16, "20", 0, hp->pipe_to_peer[1], hp->mixpipe_to_peer[0]);
  
  exit(0);
}

static void accept_peer_control(void)
{
  hub_peer_t *hp;
  int n;

  int fd = accept(control_listener, (struct sockaddr*)NULL, NULL); 
  if (fd < 0) {
    perror("accept() failed");
    return;
  }
  
  if (peer_count() == MAX_PEERS) {
    FD_CLR(listener, &active_ips);
    FD_CLR(control_listener, &active_ips);
  }
 
  buf[0] = 0;
  if (!_use_ssl) {
    // TODO add timeout
    n = recv(fd, buf, NETBUF_SIZE, 0);
    buf[n] = 0;
  }
  hp = add_peer(fd, peer_normal, buf);
  if (_use_ssl) {
    n = ssl_control_init(hp);
    if (n < 0) {
      printf("SSL failure.\n");
      peer_hangup(hp);
      return;
    }
  }
  remove_dup_peers(hp);
  n = get_nonse(hp->nonse);
  if (hubnet_ctrl_write(hp, hp->nonse, n) < 0) {
    peer_hangup(hp);
    return;
  }

  printf("accepted control for %s\n", hp->common_name);
  set_max_fd();
  FD_SET(fd, &active_ips);
}

static void accept_peer(void)
{

  int flag = 1;
  int sendbuff = 4096;
  int rcvbuff = 4096;
  int n;

  hub_peer_t *hp;

  int fd = accept(listener, (struct sockaddr*)NULL, NULL); 
  if (fd < 0) {
    perror("accept() failed");
    return;
  }
  // TODO add timeout
  n = recv(fd, buf, NONSE_LENGTH, 0);
  if (n != NONSE_LENGTH) {
    close(fd);
    return;
  }

  hp = find_peer_by_nonse(buf);

  if (!hp) {
    close(fd);
    return;
  }

  printf("accepted data for %s\n", hp->common_name);
  hp->fd = fd;
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));

  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));    
  
  FD_SET(fd, &active_ips);
  //FD_SET(fd, &active_ops);

  set_max_fd();
  hub_notify(NULL);
}

void reset_peer(hub_peer_t *hp)
{

  pid_t tmp;

  if (hp->active_call == conference_call)
    maybe_stop_timer(hp);

  if (hp->fd) {
    FD_CLR(hp->fd, &active_ips);
    FD_CLR(hp->fd, &active_ops);
  }
  if (hp->control_fd)
    FD_CLR(hp->control_fd, &active_ips);
  if (hp->pipe_to_peer[0])
    FD_CLR(hp->pipe_to_peer[0], &active_ips);
  if (hp->pipe_from_peer[1])
    FD_CLR(hp->pipe_from_peer[1], &active_ops);
  if (hp->mixpipe_from_peer[0])
    FD_CLR(hp->mixpipe_from_peer[0], &active_ips);
  if (hp->mixpipe_to_peer[1])
    FD_CLR(hp->mixpipe_to_peer[1], &active_ops);
  
  if ((tmp=hp->encoder) > 0) {
    kill(tmp, SIGKILL);
    waitpid(tmp, NULL, 0); 
  }
  
  if ((tmp=hp->decoder) > 0) {
    kill(tmp, SIGKILL);
    waitpid(tmp, NULL, 0); 
  }
  
  ssl_control_hangup(hp);
  ssl_stream_hangup(hp);
  FD_SET(listener, &active_ips);
  FD_SET(control_listener, &active_ips);
}

static int send_answer(hub_peer_t *hp)
{
  return hubnet_write(hp, "ANSWER", 6);
}

int init_peer_conf_state(hub_peer_t *hp)
{

  int ret;
  
  ret = pipe(hp->pipe_from_peer);
  ret = pipe(hp->pipe_to_peer);
  ret = pipe(hp->mixpipe_to_peer);
  ret = pipe(hp->mixpipe_from_peer);

#if 1
  ret = fcntl(hp->pipe_from_peer[0], /*F_SETPIPE_SZ*/1031, 4096);
  ret = fcntl(hp->pipe_to_peer[0], /*F_SETPIPE_SZ*/ 1031, 4096);
  ret = fcntl(hp->mixpipe_to_peer[0], /*F_SETPIPE_SZ*/ 1031, 4096);
  ret = fcntl(hp->mixpipe_from_peer[0], /*F_SETPIPE_SZ*/ 1031, 4096);
#endif
  FD_SET(hp->pipe_to_peer[0], &active_ips);
  FD_SET(hp->mixpipe_from_peer[0], &active_ips);
  FD_SET(hp->pipe_from_peer[1], &active_ops);
  FD_SET(hp->mixpipe_to_peer[1], &active_ops);
  fcntl(hp->pipe_to_peer[0], F_SETFL, O_NONBLOCK);
  fcntl(hp->pipe_from_peer[1], F_SETFL, O_NONBLOCK);
  fcntl(hp->mixpipe_from_peer[0], F_SETFL, O_NONBLOCK);
  fcntl(hp->mixpipe_to_peer[1], F_SETFL, O_NONBLOCK);

  ret = ssl_stream_init(hp);
  if (ret < 0) {
    peer_hangup(hp);
    return -1;
  }
  ret = initiate_handshake(hp);
  if (ret < 0) {
    peer_hangup(hp);
    return -1;
  }

  hp->status = peer_status_busy;
  set_max_fd();
  return 0;
}

static int parse_call(hub_peer_t *hp, char *buf, int n)
{
  hub_peer_t *other;
  int ret;
  char *ptr;

  /* No target? assume conference */
  if (n < 2 || !strcmp(buf+1, "conference")) { 
    other = call_peer_name(hp, "conference");
    init_peer_conf_state(hp);
  }
  else {
    /* Calling to itself ? */
    if (!strcmp(hp->common_name, buf+1)) {
      peer_hangup(hp);
      return -1;
    }
    
    other = call_peer_name(hp, buf + 1);    
    if (other) {
      printf("%s calling %s\n", hp->common_name, other->common_name);
      ret = strlen(hp->common_name);
      ptr = malloc(ret+3);
      if (ptr) {
	ptr[0] = 'C';
	ptr[1] = ret >> 8;
	ptr[2] = ret & 0xff;
	memcpy(ptr+3, hp->common_name, ret);
	ret = hubnet_ctrl_write(other, ptr, ret+3);
	free(ptr);
	if (ret < 0) {
	  peer_hangup(hp);
	  return -1;
	}
      }      
    }
    else {
      peer_hangup(hp);
      return -1;
    }
  }

  hub_notify(NULL);
  FD_SET(hp->fd, &active_ops);
  FD_SET(other->fd, &active_ops);
  return 0;
}

static int peer_control(hub_peer_t *hp)
{
  int n, ret = 0;
  memset(buf, 0, NETBUF_SIZE);

  n = hubnet_ctrl_read(hp, buf, NETBUF_SIZE-1);
  if (n <= 0) {
    peer_hangup(hp);
    return -1;
  }
  switch (buf[0]) {    
  case 'C':
    ret = parse_call(hp, buf+1, n-1);
    break;
  }
      
  return ret;
}

static int route_p2p(hub_peer_t *hp1, hub_peer_t *hp2)
{
  int n;
  n = recv(hp1->fd, buf, NETBUF_SIZE, 0);
  if (n <= 0) {
    peer_hangup(hp1);
    return -1;
  }
  
  n = send(hp2->fd, buf, n, MSG_NOSIGNAL);
  if (n < 0) {
    peer_hangup(hp2);
    return -1;
  }

  return 0;
}

static int initiate_handshake(hub_peer_t *hp)
{
 return hubnet_write(hp, "ACK", 3);
}

static int complete_handshake(hub_peer_t *hp)
{
  char tmp[3];
  int n;
  char tmp2[4096];
  hub_peer_t *hp2;

  n = hubnet_read(hp, tmp, 3);
  if (n <=0)
    return -1;
  
  hp->handshake_complete = 1;
  if (send_answer(hp) < 0) {
    peer_hangup(hp);
    return -1;
  }

  fork_encoder(hp);
  fork_decoder(hp);

  maybe_start_timer(hp);

  return 0;
}

static void process_control(fd_set *ips, fd_set *ops)
{
  hub_peer_t  *hp, *hp2;
 
  /* Process control io */
  list_for_each_entry_safe(hp, hp2, &peerlist, head) {
    if (FD_ISSET(hp->control_fd, ips))
      if (peer_control(hp) < 0)
	break;
  }
}

static void process_p2p(fd_set *ips, fd_set *ops)
{
  hub_peer_t  *hp, *hp2;
  call_t *c, *c2;
  
  /* Process p2p io for each p2p call */
  list_for_each_entry_safe(c, c2, &call_list, head) {
    
    hp = list_first_entry(&c->peers, hub_peer_t, peer_call);
    hp2 = list_first_entry(&hp->peer_call, hub_peer_t, peer_call);
    
    if (FD_ISSET(hp->fd, ips)  &&  FD_ISSET(hp2->fd, ops)) {
      if (route_p2p(hp, hp2) < 0)
	continue;
    }
    if (FD_ISSET(hp2->fd, ips)  &&  FD_ISSET(hp->fd, ops)) {
      if (route_p2p(hp2, hp) < 0)
	continue;
    }    
  }
}

void mixertimer(int sig)
{
  fd_set ips, ops;
  int ret;
  hub_peer_t  *hp, *hp2;
  int i, n, tmp, summed_sample;
  int16_t sample;
  int32_t mixbuf[MIXBUF_SIZE/2];
  unsigned char tmpbuf[MIXBUF_SIZE];
  struct timeval timeout;
  struct timeval tv1, res;
  
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  
  ips = active_ips;
  ops = active_ops;
  
  if ((ret = select(maxfd+1, &ips, &ops, NULL, &timeout)) <= 0) 
    return;
  
  memset(mixbuf, 0, sizeof(mixbuf));
  
  /* Get the contribution to conference talking from each peer */
  list_for_each_entry_safe(hp, hp2, &conference_call->peers, peer_call) {
    
    memset(hp->intbuf, 0, sizeof(hp->intbuf));
    if (FD_ISSET(hp->mixpipe_from_peer[0], &ips)) {
      n = read(hp->mixpipe_from_peer[0], tmpbuf, MIXBUF_SIZE);
      if (n < 0)  {
        peer_hangup(hp);
        continue;
      }
    
      tmp = 0;
      for (i=0; i < n; i+=2) {
	sample = tmpbuf[i] + tmpbuf[i+1]*256;
	hp->intbuf[tmp] = sample;
	mixbuf[tmp++] += sample;
      }
    }
  }

  /* Give peer the conference talking */
  list_for_each_entry_safe(hp, hp2, &conference_call->peers, peer_call) {
    
    /* Give peer the conference talking */
    if (hp->handshake_complete &&  FD_ISSET(hp->mixpipe_to_peer[1], &ops)) {
      for (i=0; i < MIXBUF_SIZE/2; i++) {
	summed_sample  = mixbuf[i];
	summed_sample -= hp->intbuf[i];

	if (summed_sample > SAMPLE_VALUE_MAX)
	  summed_sample = SAMPLE_VALUE_MAX;
	if (summed_sample < SAMPLE_VALUE_MIN)
	  summed_sample = SAMPLE_VALUE_MIN;

	tmpbuf[2*i]   = summed_sample & 0xff;
	tmpbuf[2*i+1] = summed_sample >> 8; 
      } 
      n = write(hp->mixpipe_to_peer[1], tmpbuf, MIXBUF_SIZE);
      
      if (n < 0)
	peer_hangup(hp);
    }  
  }

  //  gettimeofday(&tv2, NULL);
  //printf("mixertimer %d\n", (tv2.tv_usec - tv1.tv_usec));
}

static void process_conference(fd_set *ips, fd_set *ops)
{  
  hub_peer_t  *hp, *hp2;
  int n;

  /* Process conference io for each participant */
  list_for_each_entry_safe(hp, hp2, &conference_call->peers, peer_call) {

    if (FD_ISSET(hp->pipe_to_peer[0], ips) && FD_ISSET(hp->fd, ops)) {
      n = hubnet_pipe_to_sock(hp);

      if (n <= 0) {
	peer_hangup(hp);
	continue;
      }      
    }
    
    if (FD_ISSET(hp->fd, ips)) {
      if (!hp->handshake_complete) {
	if (complete_handshake(hp) < 0) {
	  peer_hangup(hp);
	}
	continue;
      }
      if (FD_ISSET(hp->pipe_from_peer[1], ops)) {
	n = hubnet_sock_to_pipe(hp);
	if (n <= 0)  {
	  peer_hangup(hp);
	  continue;
	} 
      }
    }
  }
}

static void peer_io(fd_set *ips, fd_set *ops)
{
  process_conference(ips, ops);
  process_p2p(ips, ops);
  process_control(ips, ops);

}

static void sigchld_hdl(int sig)
{
  pid_t pid;

  while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
    
  }
}

static void sigpipe_hdl (int sig)
{
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
  act.sa_handler = sigpipe_hdl;
  
  if (sigaction(SIGPIPE, &act, 0)) {
    perror ("sigaction - SIGPIPE");
    exit(1);
  }  
}

static void setup_timer(int timeout)
{
  struct itimerval it_val;      

  struct sigaction act;
  memset (&act, 0, sizeof(act));
  act.sa_handler = mixertimer;
  act.sa_flags = SA_RESTART;

  if (sigaction(SIGALRM, &act, 0)) {
    perror ("sigaction - SIGALRM");
    exit(1);
  }

  it_val.it_value.tv_sec =   0;
  it_val.it_value.tv_usec =  timeout;       
  it_val.it_interval = it_val.it_value;
  if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
    perror("error calling setitimer()");
    exit(1);
  }

}

static int maybe_start_timer(hub_peer_t *hp)
{
  if (!timer_active && call_peer_count(conference_call) >= 1) {
    timer_active = 1;
    setup_timer(20000);
  }
}

static int maybe_stop_timer(hub_peer_t *hp)
{
  
  /* Check for 2 because we-re still linked to conference call list */
  if (timer_active && call_peer_count(conference_call) == 1) {
    timer_active = 0;
    setup_timer(0);
  }
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
  { "port", hubport, "5858" },
  { "ssl", use_ssl, "false" },
  { "certfile", certfile, "" },
  { "keyfile", keyfile, "" },
  { "cafile", cafile, "" },
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

  _hubport = atoi(hubport);
  _use_ssl = !strcmp(use_ssl, "true");
  free(buf);  
}

static void parse_args(int argc, char **argv)
{

  int i;

  for(i=1; i < argc; i++) {
    if (!strcmp(argv[i], "-f") && i+1 < argc)
      strcpy(conffilename, argv[i+1]);
  }
}

int main(int argc, char **argv)
{

  int ret;

  parse_args(argc, argv);
  parse_conf();
  setup_signals();

  create_conf_call();
  
  FD_ZERO(&active_ips);
  FD_ZERO(&active_ops);

  listener = create_listener_sock(0);
  if (listener < 0)
    exit(1);

  control_listener = create_listener_sock(1);
  if (control_listener < 0)
    exit(1);

  set_max_fd();
  FD_SET(listener, &active_ips);
  FD_SET(control_listener, &active_ips);

  printf("audiohub running.\n");
  while (1) {

    memcpy(&ips, &active_ips, sizeof(fd_set));
    memcpy(&ops, &active_ops, sizeof(fd_set));
       
    if ((ret = select(maxfd+1, &ips, &ops, NULL, NULL)) < 0) {
      continue;
    }

    if (peer_count() < MAX_PEERS && FD_ISSET(control_listener, &ips))
      accept_peer_control();

    if (peer_count() <= MAX_PEERS && FD_ISSET(listener, &ips))
      accept_peer();

    peer_io(&ips, &ops);
  }

  return 0;
}
