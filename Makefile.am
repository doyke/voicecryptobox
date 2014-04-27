
#AUTOMAKE_OPTIONS = subdir-objects 1.6 dist-zip
AUTOMAKE_OPTIONS = subdir-objects 1.11 dist-zip dist-xz

SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src -I$(top_srcdir)/win32

AM_CFLAGS = $(OGG_CFLAGS) $(Opus_CFLAGS) -DOPUSTOOLS -D_FORTIFY_SOURCE=2 -DHAVE_GETOPT_H -DSPX_RESAMPLE_EXPORT= -DRANDOM_PREFIX=opustools -DOUTSIDE_SPEEX -DFLOATING_POINT

bin_PROGRAMS = audioengine audiohub

noinst_HEADERS = src/arch.h \
                 src/diag_range.h \
                 src/info_opus.h \
                 src/lpc.h \
                 src/opusenc.h \
                 src/opus_header.h \
                 src/opusinfo.h \
                 src/os_support.h \
                 src/resample_sse.h \
                 src/speex_resampler.h \
                 src/stack_alloc.h \
                 win32/unicode_support.h \
                 src/cpusupport.h \
                 src/wave_out.h \
                 src/wav_io.h

EXTRA_DIST = Makefile.unix \
	     man/opusrtp.1 \
             opus-tools.sln \
             src/opusdec.vcxproj.filters \
             src/opusinfo.vcxproj.filters \
             src/opusenc.vcxproj.filters \
             src/opusinfo.vcxproj \
             src/opusenc.vcxproj \
             src/opusdec.vcxproj \
             include/getopt.h \
             share/getopt.c \
             share/getopt1.c \
             win32/genversion.bat \
             win32/config.h \
             win32/unicode_support.h \
             win32/unicode_support.c \
             win32/version.h

#dist_man_MANS = man/opusenc.1 man/opusdec.1 man/opusinfo.1

audioengine_SOURCES = src/audioengine.c src/pcm.c src/net_io.c src/sched.c src/opus_header.c src/opusenc.c src/opusdec_engine.c src/wav_io.c src/wave_out.c src/resample.c src/audio-in.c src/diag_range.c src/lpc.c win32/unicode_support.c
audioengine_LDADD = $(OGG_LIBS) $(Opus_LIBS) -lm -lasound -lssl -lcrypto
audioengine_MANS = man/opusenc.1

audiohub_SOURCES = src/audiohub2.c src/hubnet.c src/peers.c src/call.c src/sched.c src/opus_header.c src/opusenc.c src/opusdec.c src/wav_io.c src/wave_out.c src/resample.c src/audio-in.c  src/diag_range.c src/lpc.c win32/unicode_support.c src/pcm.c
audiohub_LDADD = $(OGG_LIBS) $(Opus_LIBS) -lm -lasound -lssl -lcrypto

#TESTS = FIXME
