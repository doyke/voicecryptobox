#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <string.h>

#include <alsa/asoundlib.h>

#include "peer.h"

static int bridge_status[MAX_PEERS];

typedef struct _bridge_channel_t {
  const char *audiodevice;
  snd_pcm_t *handle;
} bridge_channel_t;

static bridge_channel_t bridge_channels[MAX_PEERS];

const char *audiodevice_names[] = {
  "bridgechannel0",
  "bridgechannel1",
  "bridgechannel2",
  "bridgechannel3",
  "bridgechannel4",
  "bridgechannel5",
  "bridgechannel6",
  "bridgechannel7",
};

static snd_pcm_uframes_t  _buffersize;
static snd_pcm_uframes_t period_frames;


static int configure_buffers_periods(snd_pcm_t *handle, snd_pcm_hw_params_t *params)
{
  unsigned int     period_time_min;
  unsigned int     period_time_max;
  unsigned int     buffer_time_min;
  unsigned int     buffer_time_max;
  snd_pcm_uframes_t     buffersize, periodsize;

  unsigned int val, val2, targetbuffertime;
  int err;

  snd_pcm_hw_params_get_buffer_time_min(params, &buffer_time_min, 0);
  snd_pcm_hw_params_get_buffer_time_max(params, &buffer_time_max, 0);
  snd_pcm_hw_params_get_period_time_min(params, &period_time_min, 0);
  snd_pcm_hw_params_get_period_time_max(params, &period_time_max, 0);
  printf("  Buffer time range from %u ms to %u ms\n", buffer_time_min/1000, buffer_time_max/1000);
  printf("  Period time range from %u ms to %u ms\n", period_time_min/1000, period_time_max/1000);


  targetbuffertime = 60000; 
 __again:
  targetbuffertime += 20000; /* 20ms */

  if (targetbuffertime > 1000000) {
    printf("Cannot configure buffer time..giving up.\n");
    return -1;
  }
    
  printf("  ..trying to configure buffer size of %u ms\n",targetbuffertime/1000);
  err = snd_pcm_hw_params_set_buffer_time_near(handle, params, &targetbuffertime, 0);
  if (err < 0) 
    goto __again;

  snd_pcm_hw_params_get_buffer_size(params, &buffersize);
  val = 20000;
  err = snd_pcm_hw_params_set_period_time_near(handle, params, &val, 0);
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

  printf("Bridgechannel configure OK: period = %u ms, buffer = %u ms\n", val/1000, val2/1000);
}


int bridge_initialize(void)
{
  int i;
  int err, dir;
  unsigned int rate = 48000;
 
  snd_pcm_hw_params_t *hw_params;
  snd_pcm_sw_params_t *sw_params;

  snd_pcm_t *handle;
  
  for (i=0; i < MAX_PEERS; i++) {
    
    bridge_channels[i].audiodevice = audiodevice_names[i];
    if ((err = snd_pcm_open (&handle,
			     bridge_channels[i].audiodevice,
			     SND_PCM_STREAM_PLAYBACK, 0)) < 0) {
      fprintf (stderr, "bridge : cannot open audio device %s (%s)\n", 
	       "default",
	       snd_strerror (err));
      return -1;
    }
    bridge_channels[i].handle = handle;
    
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
    
    if ((err = snd_pcm_hw_params_set_access (handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED))
	< 0) {
      fprintf (stderr, "cannot set access type (%s)\n",
	       snd_strerror (err));
      return -1;
    }
           
    if ((err = snd_pcm_hw_params_set_format (handle, hw_params, SND_PCM_FORMAT_S16_LE)) < 0) {
      fprintf (stderr, "cannot set sample format (%s)\n",
	       snd_strerror (err));
      return -1;
    }
    if ((err = snd_pcm_hw_params_set_rate_near (handle, hw_params, &rate, 0)) < 0) {
      fprintf (stderr, "cannot set sample rate (%s)\n",
	       snd_strerror (err));
      return -1;
    }
    if ((err = snd_pcm_hw_params_set_channels (handle, hw_params, 1)) < 0) {
      fprintf (stderr, "cannot set channel count (%s)\n",
	       snd_strerror (err));
      return -1;
    }

    configure_buffers_periods(handle, hw_params);

    if ((err = snd_pcm_hw_params (handle, hw_params)) < 0) {
      fprintf (stderr, "cannot set parameters (%s)\n",
	       snd_strerror (err));
      return -1;
    }
    snd_pcm_hw_params_free (hw_params);
    snd_pcm_sw_params_current(handle, sw_params);
    snd_pcm_sw_params_set_start_threshold(handle, sw_params, _buffersize - period_frames);
    if ((err = snd_pcm_sw_params(handle, sw_params)) < 0) {
      fprintf(stderr, "cannot set sw parameters (%s)\n", snd_strerror(err));
      return -1;
    }


  }
  return 0;
}


int bridge_allocate_channel(void) 
{
  int i;

  for (i=0; i < MAX_PEERS; i++) {
    if (!bridge_status[i]) {
      bridge_status[i] = 1;
      break;
    }
  }

  return (i >= MAX_PEERS ? -1 : i);
}

const char *bridge_channel_devicename(int i)
{
  return bridge_channels[i].audiodevice;
}

void bridge_free_channel(int channel)
{
  bridge_status[channel] = 0;
}

void bridge_write(int writer, unsigned char *data, int len)
{
  int i, nwrite;
  snd_pcm_uframes_t samples;

  samples = len/2; /* 2 bytes per sample, one channel */
  for (i=0; i < MAX_PEERS; i++) {
    if (bridge_status[i] && writer != i) {
      if ((nwrite = snd_pcm_writei(bridge_channels[i].handle, data, samples)) < 0) {
	fprintf (stderr, "bridge : write to audio interface failed (%s)\n",
		 snd_strerror (nwrite));
	snd_pcm_recover(bridge_channels[i].handle, nwrite, 0);      
      }
    }

  }
}


