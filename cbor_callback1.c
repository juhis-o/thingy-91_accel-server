#include "cbor_callback1.h"

uint8_t miscInfo = 0;
uint8_t timestamp_loc = 0;
uint64_t timestamp;
int numberOfitems = 0;
bool firstBrack = true;

void cbor_setcallbacks(struct cbor_callbacks callbacks){
    callbacks.uint8 = find_uint8;
	callbacks.negint8 = find_int8;
	callbacks.uint16 = find_uint16;
	callbacks.negint16 = find_int16;
	callbacks.uint32 = find_uint32;
	callbacks.negint32 = find_int32;
	callbacks.uint64 = find_uint64;
	callbacks.negint64 = find_int64;
	callbacks.array_start = find_arr_start;
}

void find_uint8(void* ctx, unsigned char buffer){
    if(miscInfo <= 3){
        if(miscInfo == 0){
            timestamp = buffer;
        }
        else if(miscInfo == 3){
            fprintf(ctx,"%d\t",buffer);
        }
        else {
            fprintf(ctx,"\t%d\t",buffer);
        }
        miscInfo++;
    }
    else {
        if(timestamp_loc == 170){
            fprintf(ctx,"%ld\t\t%d\t", timestamp,buffer);
            timestamp_loc = 0;
        }
    
        else {
            fprintf(ctx,"\t\t%d\t", buffer);
        }
    }
}

void find_int8(void* ctx, unsigned char buffer){
    if(miscInfo <= 3){
        fprintf(ctx,"\t%d\t",-1 - buffer);
        miscInfo++;
    }
    else {
        if(timestamp_loc == 170){
            fprintf(ctx,"%ld\t\t%d\t", timestamp,-1 - buffer);
            timestamp_loc = 0;
        }
        else {
        fprintf(ctx,"\t\t%d\t",-1 - buffer);
        }
    }
}

void find_uint16(void* ctx, uint16_t buffer){
    if(miscInfo <= 3){
        if(miscInfo == 0){
            timestamp = buffer;
        }
        else if(miscInfo == 3){
            fprintf(ctx,"%d\t",buffer);
        }
        else {
            fprintf(ctx,"\t%d\t",buffer);
        }
        miscInfo++;
    }
    else {
        if(timestamp_loc == 170){
            fprintf(ctx,"%ld\t\t%d\t",timestamp,buffer);
            timestamp_loc = 0;
        }
        else {
            fprintf(ctx,"\t\t%d\t",buffer);
        }
    }
}

void find_int16(void* ctx, uint16_t buffer){
    if(miscInfo <= 3){
        fprintf(ctx,"\t%d\t",-1 - buffer);
        miscInfo++;
    }
  
    else {
        if(timestamp_loc == 170){
            fprintf(ctx,"%ld\t\t%d\t",timestamp,-1-buffer);
            timestamp_loc = 0;
        }
        else {
            fprintf(ctx,"\t\t%d\t",-1 - buffer);
        }
    }
}

void find_uint32(void* ctx, uint32_t buffer){
    if(miscInfo <= 3){
        if(miscInfo == 0){
            timestamp = buffer;
        }
        else if(miscInfo == 3){
            fprintf(ctx,"%d\t",buffer);
        }
        else {
            fprintf(ctx,"\t%d\t",buffer);
        }
    miscInfo++;  
    }
  
    else {
        fprintf(ctx,"\t\t%d\t",buffer);
    }
}

void find_int32(void* ctx, uint32_t buffer){
    if(miscInfo <= 3){
        fprintf(ctx,"\t%d\t",-1 - buffer);
        miscInfo++;
    }
    else {
        fprintf(ctx,"\t%d\t",-1 - buffer);
    }
}

void find_uint64(void* ctx, uint64_t buffer){
    if(miscInfo <= 3){
        if(miscInfo == 0){
            timestamp = buffer;
        }
        else if(miscInfo == 3){
            fprintf(ctx,"%ld\t",buffer);
        }
        else {
            fprintf(ctx,"\t%ld\t",buffer);
        }
        miscInfo++;
    }
    else {
        fprintf(ctx,"\t\t%ld\t",buffer);
    }
}

void find_int64(void* ctx, uint64_t buffer){
    if(miscInfo <= 3){
        fprintf(ctx,"\t%ld\t",-1 - buffer);
        miscInfo++;
    }
    else {
        fprintf(ctx,"\t%ld\t",-1 - buffer);
    }
}

void find_arr_start(void* ctx, long unsigned int test){
    if(firstBrack){
        if(timestamp_loc == 170){
            fprintf(ctx,"\n\t%ld\nItem: %d",timestamp, numberOfitems);
            numberOfitems++;
            firstBrack = false;
            timestamp_loc = 0;
        }
        else {
            fprintf(ctx,"\nItem: %d", numberOfitems);
            numberOfitems++;
            timestamp_loc--;
            firstBrack = false;
        }

    }
    else {
        fprintf(ctx,"\n");
        timestamp_loc++;
    }
}