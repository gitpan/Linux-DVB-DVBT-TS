/* Hand hacked to minimal config */

/* include/config.h.  Generated from config.h.in by configure.  */
/* include/config.h.in.  Generated from configure.ac by autoheader.  */

/* autodetect accelerations */
//#define ACCEL_DETECT /**/

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* alpha architecture */
/* #undef ARCH_ALPHA */

/* ARM architecture */
/* #undef ARCH_ARM */

/* ppc architecture */
/* #undef ARCH_PPC */

/* sparc architecture */
/* #undef ARCH_SPARC */

/* x86 architecture */
//#define ARCH_X86 /**/

/* maximum supported data alignment */
// include/attributes.h
//#define ATTRIBUTE_ALIGNED_MAX 64

/* debug mode configuration */
/* #undef DEBUG */

/* Define to 1 if you have the <altivec.h> header. */
/* #undef HAVE_ALTIVEC_H */

/* Define if you have the `__builtin_expect' function. */
//#define HAVE_BUILTIN_EXPECT /**/

/* Define to 1 if you have the `ftime' function. */
//NOT NEEDED//#define HAVE_FTIME 1

/* Define to 1 if you have the `gettimeofday' function. */
//NOT NEEDED//#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <inttypes.h> header file. */
//NOT NEEDED//#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <io.h> header file. */
/* #undef HAVE_IO_H */

/* Define to 1 if you have the <memory.h> header file. */
//NOT NEEDED//#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
//NOT NEEDED//#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
//NOT NEEDED//#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
//NOT NEEDED//#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
//NOT NEEDED//#define HAVE_STRING_H 1

/* Define to 1 if the system has the type `struct timeval'. */
//NOT NEEDED//#define HAVE_STRUCT_TIMEVAL 1

/* Define to 1 if you have the <sys/stat.h> header file. */
//NOT NEEDED//#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/timeb.h> header file. */
//NOT NEEDED//#define HAVE_SYS_TIMEB_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
//NOT NEEDED//#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
//NOT NEEDED//#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <time.h> header file. */
//NOT NEEDED//#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
//NOT NEEDED//#define HAVE_UNISTD_H 1

/* mpeg2dec profiling */
/* #undef MPEG2DEC_GPROF */



/* Name of package */
#define PACKAGE "libmpeg2"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "libmpeg2"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libmpeg2 0.5.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libmpeg2"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.5.1"

/* Define as the return type of signal handlers (`int' or `void'). */
// cpu_accel.c
// ALWAYS void
#define RETSIGTYPE void

/* The size of `char', as computed by sizeof. */
/* #undef SIZEOF_CHAR */

/* The size of `int', as computed by sizeof. */
/* #undef SIZEOF_INT */

/* The size of `long', as computed by sizeof. */
/* #undef SIZEOF_LONG */

/* The size of `short', as computed by sizeof. */
/* #undef SIZEOF_SHORT */

/* The size of `void*', as computed by sizeof. */
/* #undef SIZEOF_VOIDP */

/* Define to 1 if you have the ANSI C header files. */
//NOT NEEDE//#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
//NOT NEEDE//#define TIME_WITH_SYS_TIME 1

/* Version number of package */
#define VERSION "0.5.1"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
// convert/uyvy.c
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
#define _FILE_OFFSET_BITS 64

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
//#ifndef __cplusplus
//#define inline __attribute__ ((__always_inline__))
//#endif

/* Define as `__restrict' if that's what the C compiler calls it, or to
   nothing if it is not supported. */
//NOT NEEDED//#define restrict __restrict__

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */