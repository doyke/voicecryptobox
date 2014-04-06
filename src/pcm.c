#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <string.h>

#include <alsa/asoundlib.h>

static snd_pcm_t *handle;
static char *buf;
static int buf_bytes;
static int buf_ptr;

static int sample_size;
size_t target_bytes;
size_t samplebuffer_size;

snd_pcm_format_t _pcmformat;
unsigned int period_time;

snd_pcm_uframes_t  _buffersize;
snd_pcm_uframes_t period_frames;

extern int loopbackpipe[2];
extern int _loopback;
int mixpipe = -1;

extern void go_realtime(int record);
static int configure_buffers_periods(int record, snd_pcm_hw_params_t *params)
{
  unsigned int     period_time_min;
  unsigned int     period_time_max;
  unsigned int     buffer_time_min;
  unsigned int     buffer_time_max;
  snd_pcm_uframes_t     buffersize, periodsize;

  unsigned int val, val2, targetbuffertime;
  int err;

  if (!record)
    printf("Configuring ALSA buffers for playback.\n");
  else
    printf("Configuring ALSA buffers for record.\n");

  snd_pcm_hw_params_get_buffer_time_min(params, &buffer_time_min, 0);
  snd_pcm_hw_params_get_buffer_time_max(params, &buffer_time_max, 0);
  snd_pcm_hw_params_get_period_time_min(params, &period_time_min, 0);
  snd_pcm_hw_params_get_period_time_max(params, &period_time_max, 0);
  printf("  Buffer time range from %u ms to %u ms\n", buffer_time_min/1000, buffer_time_max/1000);
  printf("  Period time range from %u ms to %u ms\n", period_time_min/1000, period_time_max/1000);

  //targetbuffertime = 140000; /* 140ms */
  //targetbuffertime = 30000; 
  targetbuffertime = 60000; 
 __again:
  targetbuffertime += 20000; /* 20ms */
  //  targetbuffertime += 20000; /* 20ms */
  if (targetbuffertime > 1000000) {
    printf("Cannot configure buffer time..giving up.\n");
    return -1;
  }
    
  printf("  ..trying to configure buffer size of %u ms\n",targetbuffertime/1000);
  err = snd_pcm_hw_params_set_buffer_time_near(handle, params, &targetbuffertime, 0);
  if (err < 0) 
    goto __again;

  snd_pcm_hw_params_get_buffer_size(params, &buffersize);

#if 0
  periodsize = buffersize / 16;
  err = snd_pcm_hw_params_set_period_size_near(handle, params, &periodsize, 0);
#endif
#if 1
  val = 20000;
  //val = 10000;
  err = snd_pcm_hw_params_set_period_time_near(handle, params, &val, 0);
#endif
  if (err < 0)
    goto __again;

   snd_pcm_hw_params_get_period_size(params, &periodsize, NULL);
   snd_pcm_hw_params_get_buffer_size(params, &buffersize);
   if (periodsize * 2 > buffersize)
     goto __again;

   _buffersize = buffersize;
   period_frames = periodsize;

   snd_pcm_hw_params_get_period_time(params, &val, 0);
   snd_pcm_hw_params_get_buffer_time(params, &val2, 0);

   printf("Configure OK: period = %u ms, buffer = %u ms\n", val/1000, val2/1000);

   return 0;
}

int open_pcm(const char *audiodevice, int record, unsigned int rate, char *format, unsigned int buffersize, unsigned int channels, unsigned int bits, int _pipe)
{
  int err, dir;

  snd_pcm_hw_params_t *hw_params;
  snd_pcm_sw_params_t *sw_params;
  snd_pcm_stream_t     stream = record ? SND_PCM_STREAM_CAPTURE : SND_PCM_STREAM_PLAYBACK;
  _buffersize = buffersize;

  if (_loopback)
    return 0;

  mixpipe = _pipe;

  if (mixpipe >= 0)
    return 0;

  go_realtime(record);

  if(strstr(format, "LE"))
    _pcmformat = SND_PCM_FORMAT_S16_LE;
  else
    _pcmformat = SND_PCM_FORMAT_S16_BE;

  sample_size = bits * channels / 8;

  if ((err = snd_pcm_open (&handle, audiodevice, stream, 0)) < 0) {
    fprintf (stderr, "cannot open audio device %s (%s)\n", 
	     "default",
	     snd_strerror (err));
    return -1;
  }

  if ((err = snd_pcm_hw_params_malloc (&hw_params)) < 0) {
    fprintf (stderr, "cannot allocate hardware parameter structure (%s)\n",
	     snd_strerror (err));
    return -1;
  }

  snd_pcm_sw_params_alloca(&sw_params);
				 
  if ((err = snd_pcm_hw_params_any (handle, hw_params)) < 0) {
    fprintf (stderr, "cannot initialize hardware parameter structure (%s)\n",
	     snd_strerror (err));
    return -1;
  }
	
  if ((err = snd_pcm_hw_params_set_access (handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED)) < 0) {
    fprintf (stderr, "cannot set access type (%s)\n",
	     snd_strerror (err));
    return -1;
  }
	
  if ((err = snd_pcm_hw_params_set_format (handle, hw_params, _pcmformat)) < 0) {
    fprintf (stderr, "cannot set sample format (%s)\n",
	     snd_strerror (err));
    return -1;
  }

  if ((err = snd_pcm_hw_params_set_rate_near (handle, hw_params, &rate, 0)) < 0) {
    fprintf (stderr, "cannot set sample rate (%s)\n",
	     snd_strerror (err));
    return -1;
  }

  printf("Rate set to %d\n", rate);
	
  if ((err = snd_pcm_hw_params_set_channels (handle, hw_params, channels)) < 0) {
    fprintf (stderr, "cannot set channel count (%s)\n",
	     snd_strerror (err));
    return -1;
  }

  if (configure_buffers_periods(record, hw_params) < 0)
    return -1;
#if 0

  period_time = 20000;
  dir = 0;
  if ((err = snd_pcm_hw_params_set_period_time_near(handle, hw_params,
						    &period_time, &dir)) < 0) {
    
    fprintf (stderr, "cannot set period size  (%s)\n",
	     snd_strerror (err));
    return -1;
  }
  snd_pcm_hw_params_get_period_size(hw_params, &period_frames, 0);
  //snd_pcm_hw_params_get_buffer_size(hw_params, &_buffersize); 	
  
  _buffersize=4*period_frames;

  if ((err = snd_pcm_hw_params_set_buffer_size_near(handle, hw_params, &_buffersize)) < 0) {
    fprintf (stderr, "cannot set buffer size  (%s)\n", snd_strerror (err));
    return -1;
  }

#endif
#if 0
  if ((err = snd_pcm_hw_params_set_buffer_size_near(handle, hw_params, &_buffersize)) < 0) {
    fprintf (stderr, "cannot set buffer size  (%s)\n",
	     snd_strerror (err));
    return -1;
  }

  //period_frames = _buffersize / 16;
period_frames = _buffersize / 8;

  if ((err = snd_pcm_hw_params_set_period_size_near(handle, hw_params,
						    &period_frames, 0)) < 0) {
    
    fprintf (stderr, "cannot set period size  (%s)\n",
	     snd_strerror (err));
    return -1;
  }

#endif	
  if ((err = snd_pcm_hw_params (handle, hw_params)) < 0) {
    fprintf (stderr, "cannot set parameters (%s)\n",
	     snd_strerror (err));
    return -1;
  }
	
  snd_pcm_hw_params_free (hw_params);

  snd_pcm_sw_params_current(handle, sw_params);

#if 1
  if (!record)
    snd_pcm_sw_params_set_start_threshold(handle, sw_params, _buffersize - period_frames);
  else
    snd_pcm_sw_params_set_start_threshold(handle, sw_params, period_frames);
  
#endif
#if 0
  if (!record)
    snd_pcm_sw_params_set_start_threshold(handle, sw_params, _buffersize/2);
  else
    snd_pcm_sw_params_set_start_threshold(handle, sw_params, _buffersize/4);

#endif
#if 1

    
    snd_pcm_uframes_t boundary;
    
    snd_pcm_sw_params_get_boundary(sw_params, &boundary);
    printf("alsa boundary : %lu\n", boundary);
    
    snd_pcm_sw_params_set_stop_threshold(handle, sw_params, boundary);


#endif

  if ((err = snd_pcm_sw_params(handle, sw_params)) < 0) {
    fprintf(stderr, "cannot set sw parameters (%s)\n", snd_strerror(err));
    return -1;
  }

  target_bytes = period_frames * sample_size;

  /* We need at most twice the period size of buffer */
  samplebuffer_size = 2*target_bytes;
  buf = malloc(samplebuffer_size);
  if (!buf) {
    fprintf (stderr, "cannot allocate recorder buffer\n");
    return -1;
  }

  return 0;
}

void close_pcm(void) 
{

  if (_loopback || mixpipe >= 0)
    return;

  snd_pcm_drain(handle);	
  snd_pcm_close (handle);
  free(buf);
  exit(0);
}

int write_to_pcm(char *ptr, int n)
{

  snd_pcm_uframes_t samples;
  int nwrite, tmp, copied = 0;

  snd_pcm_uframes_t target_frames;
  samples = n / sample_size;
  
  if (mixpipe >= 0) {
    tmp = write(mixpipe, ptr, n);
    return n;
  }
  
#if 1
  //printf("got %d %d samples\n", samples, period_frames);
  if (_loopback) {
    n = write(loopbackpipe[1], ptr, n);
    return n;
  }


  if ((nwrite = snd_pcm_writei(handle, ptr, samples)) < 0) {
    fprintf (stderr, "write to audio interface failed (%s)\n",
	     snd_strerror (nwrite));
    snd_pcm_drop(handle);
    snd_pcm_prepare(handle);
    //snd_pcm_recover(handle, nwrite, 0);      
    
  }
  return n;
#endif
  
#if 0
  if (_loopback) {
    n = write(loopbackpipe[1], ptr, n);
    return n;
  }

  memcpy(buf, ptr, n);
  if (samples < period_frames) {
    //printf("got %d/%d\n", samples, period_frames);
    tmp = samples*sample_size;
    snd_pcm_format_set_silence(_pcmformat, buf + tmp, (period_frames - samples));
    samples = period_frames;
  } 

  target_frames = period_frames;
  while (target_frames) {
    if ((nwrite = snd_pcm_writei(handle, buf, target_frames)) < 0) {
      fprintf (stderr, "write to audio interface failed (%s)\n",
	       snd_strerror (nwrite));
      snd_pcm_recover(handle, nwrite, 0);      
      continue;
    }
    target_frames -= nwrite;
  }
  return n;

#endif

  tmp = buf_bytes/sample_size;
  if (tmp + samples < period_frames) {
    memcpy(buf+buf_ptr, ptr, n);
    buf_bytes += n;
    buf_ptr += n;
    return n;
  }

  tmp = target_bytes - buf_bytes;
  memcpy(buf+buf_ptr, ptr, tmp);
  copied = tmp;
  buf_bytes += tmp;
  n -= tmp;

  while (buf_bytes >= target_bytes) {
    
    target_frames = period_frames;

    buf_ptr = 0;
    while (target_frames) {
      if ((nwrite = snd_pcm_writei (handle, buf+buf_ptr, target_frames)) < 0) {
	fprintf (stderr, "write to audio interface failed (%s)\n",
		 snd_strerror (nwrite));
	snd_pcm_recover(handle, nwrite, 0);      
      continue;
      }
      target_frames -= nwrite;
      buf_bytes -= nwrite*sample_size;
      buf_ptr += nwrite*sample_size;
    
    }

    tmp = target_bytes;
    tmp = tmp > n ? n : tmp;
    
    memcpy(buf, ptr+copied, tmp);
    buf_bytes += tmp;
    buf_ptr = tmp;
    copied += tmp;
    n -= tmp;
 
  }
  
  return copied;
}

int read_from_pcm(char *ptr, int n)
{

  snd_pcm_uframes_t target_frames;
  int nread, tmp;
  int copied = 0;
 
#if 1
  if(_loopback) {
    while (n) {
      tmp = read(loopbackpipe[0], ptr+copied, n);
      if (tmp < 0)
	return tmp;
      if (!tmp)
	return copied;
      
      copied += tmp;
      n -= tmp;
    }
    return copied;
  }
  

  if (mixpipe >= 0) {

    while (n) {
      tmp = read(mixpipe, ptr+copied, n);
      if (tmp < 0)
	return tmp;
      if (!tmp)
	return copied;
      copied += tmp;
      n -= tmp;
    }
    return copied;
  }
  
  if ((nread = snd_pcm_readi (handle, ptr, n/sample_size)) < 0) {
    fprintf (stderr, "read from audio interface failed (%s)\n",
	     snd_strerror (nread));
    /* recover */
    snd_pcm_prepare(handle);
    
  }
  return n;
    
    
#endif

  if (buf_bytes >= n) {
    memcpy(ptr, buf + buf_ptr, n);
    buf_bytes -=n ;
    buf_ptr += n;
    return n;
  }

  if (buf_bytes) {
    memcpy(ptr, buf + buf_ptr, buf_bytes);
    n -= buf_bytes;
    copied += buf_bytes;
  }

  while (n) {
    
    target_frames = period_frames;
    
    buf_ptr = 0;
    buf_bytes = 0;
    
    while (target_frames) {
      if ((nread = snd_pcm_readi (handle, buf + buf_bytes, period_frames)) < 0) {
	fprintf (stderr, "read from audio interface failed (%s)\n",
		 snd_strerror (nread));
	/* recover */
	snd_pcm_prepare(handle);
	continue;
      }
      target_frames -= nread;
      buf_bytes += nread*sample_size;
    }
   
    tmp = (n > buf_bytes) ? buf_bytes : n;

    memcpy(ptr+copied, buf, tmp);
    buf_ptr = tmp;
    buf_bytes -= tmp;
    
    copied += tmp;
    n -= tmp;
  }
  return copied;
}
