ifndef libdvb_ts_lib
libdvb_ts_lib := .
endif

CFLAGS += -I$(libdvb_ts_lib)

OBJS-libdvb_ts_lib := \
	$(libdvb_ts_lib)/ts_parse.o \
	$(libdvb_ts_lib)/ts_skip.o \
	$(libdvb_ts_lib)/ts_split.o \
	$(libdvb_ts_lib)/ts_cut.o
