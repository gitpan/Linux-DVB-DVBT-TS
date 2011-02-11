mpeg2audio ?= .

CFLAGS += -I$(mpeg2audio)

OBJS-mpeg2audio := \
	$(mpeg2audio)/mpegaudio_stubs.o
