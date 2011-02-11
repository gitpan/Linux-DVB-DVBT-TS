ifndef libdvb_lib
libdvb_lib := .
endif

CFLAGS += -I$(libdvb_lib)

OBJS-libdvb_lib := \
	$(libdvb_lib)/dvb_error.o 
	