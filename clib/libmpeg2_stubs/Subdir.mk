libmpeg2 ?= .

CFLAGS += -I$(libmpeg2) -I$(libmpeg2)/include

OBJS-libmpeg2 := \
	$(libmpeg2)/mpeg2_stubs.o
