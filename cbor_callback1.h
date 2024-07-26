#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <cbor.h>
#include <stdint.h>

void cbor_setcallbacks(struct cbor_callbacks callbacks);
void find_uint8(void* ctx, unsigned char buffer);
void find_int8(void* ctx, unsigned char buffer);
void find_uint16(void* ctx, uint16_t buffer);
void find_int16(void* ctx, uint16_t buffer);
void find_uint32(void* ctx, uint32_t buffer);
void find_int32(void* ctx, uint32_t buffer);
void find_uint64(void* ctx, uint64_t buffer);
void find_int64(void* ctx, uint64_t buffer);
void find_arr_start(void* ctx, long unsigned int test);

#endif //CALLBACKS_H