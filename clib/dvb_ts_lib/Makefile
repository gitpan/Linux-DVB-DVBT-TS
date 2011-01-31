CFLAGS   := -g
ifdef DEBUG
CFLAGS   += -O0
else
CFLAGS   += -O3
endif
CFLAGS   += -pedantic
CFLAGS   += -std=gnu99
CFLAGS   += -fPIC
CFLAGS   += -I.
CFLAGS   += -D_LARGEFILE_SOURCE
CFLAGS   += -D_FILE_OFFSET_BITS=64
CFLAGS   += -D_GNU_SOURCE

ifdef TESTDEF
	CFLAGS += -D $(TESTDEF)
endif

# libdvb_ts_lib
libdvb_ts_lib := ../dvb_ts_lib
include $(libdvb_ts_lib)/Subdir.mk

# libmpeg2
ifdef HAVE_MPEG2
libmpeg2 := ../libmpeg2
else
libmpeg2 := ../libmpeg2_stubs
endif
include $(libmpeg2)/Subdir.mk

# mpeg2audio
ifdef HAVE_AUDIO
mpeg2audio := ../mpeg2audio
else
mpeg2audio := ../mpeg2audio_stubs
endif
include $(mpeg2audio)/Subdir.mk

# libdvb_lib
libdvb_lib := ../dvb_lib
CFLAGS += -I$(libdvb_lib)
OBJS-libdvb_lib := \
	$(libdvb_lib)/dvb_error.o


OBJS := \
$(OBJS-libdvb_ts_lib) \
$(OBJS-libmpeg2) \
$(OBJS-mpeg2audio) \
$(OBJS-libdvb_lib)


libdvb_ts_lib.a: $(OBJS)
	$(AR) cr libdvb_ts_lib.a $(OBJS)
	ranlib libdvb_ts_lib.a

clean::
	rm -f libdvb_ts_lib.a
	rm -f *.o
	rm -f $(libmpeg2)/*.a
	rm -f $(libmpeg2)/*.o
	rm -f $(mpeg2audio)/*.a
	rm -f $(mpeg2audio)/*.o
	rm -f $(libdvb_lib)/*.a
	rm -f $(libdvb_lib)/*.o
	rm -f $(libdvb_ts_lib)/*.a
	rm -f $(libdvb_ts_lib)/*.o

