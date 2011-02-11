/*
 * mpeg2_stubs.c
 *
 *  Created on: 27 Oct 2010
 *      Author: sdprice1
 */

#include <stdint.h>
#include "mpeg2.h"



uint32_t mpeg2_accel (uint32_t accel) {return 0;}
mpeg2dec_t * mpeg2_init (void) {return 0;}
const mpeg2_info_t * mpeg2_info (mpeg2dec_t * mpeg2dec) {return 0;}
void mpeg2_close (mpeg2dec_t * mpeg2dec) {}

void mpeg2_buffer (mpeg2dec_t * mpeg2dec, uint8_t * start, uint8_t * end) {}
int mpeg2_getpos (mpeg2dec_t * mpeg2dec) {return 0;}
mpeg2_state_t mpeg2_parse (mpeg2dec_t * mpeg2dec) {return 0;}

void mpeg2_reset (mpeg2dec_t * mpeg2dec, int full_reset) {}
void mpeg2_skip (mpeg2dec_t * mpeg2dec, int skip) {}
void mpeg2_slice_region (mpeg2dec_t * mpeg2dec, int start, int end) {}

void mpeg2_tag_picture (mpeg2dec_t * mpeg2dec, uint32_t tag, uint32_t tag2) {}

void mpeg2_init_fbuf (mpeg2_decoder_t * decoder, uint8_t * current_fbuf[3],
		      uint8_t * forward_fbuf[3], uint8_t * backward_fbuf[3]) {}
void mpeg2_slice (mpeg2_decoder_t * decoder, int code, const uint8_t * buffer) {}
int mpeg2_guess_aspect (const mpeg2_sequence_t * sequence,
			unsigned int * pixel_width,
			unsigned int * pixel_height) {return 0;}

void * mpeg2_malloc (unsigned size, mpeg2_alloc_t reason) {return 0;}
void mpeg2_free (void * buf) {}
void mpeg2_malloc_hooks (void * malloc (unsigned, mpeg2_alloc_t),
			 int free (void *)) {}

