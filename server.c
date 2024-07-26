#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include "coap3/coap.h"
#include "heatshrink_decoder.h"
#include "shared.h"
#include "cbor_callback1.h"

static FILE *fp;

uint8_t payload[160][1100];
bool received[10] = {0};
size_t input_data[160];

#define PSK_IDENTITY "serv"

int packets = 0;
extern bool firstBrack;
extern uint8_t miscInfo; 

uint8_t vastaanotettu = 0;

static const char *hint = "CoAP";

static valid_psk_snis_t valid_psk_snis = {0, NULL};

union received_msgs{
  uint16_t num;
  uint8_t bytes[2];
} confirm_payload;

int kymmenekset = 0;
struct cbor_callbacks callbacks;
extern uint8_t psk[16];
extern uint8_t psk_len;


size_t heatshrink_decompression(uint8_t* input_data, uint16_t input_len, uint8_t* output_data, size_t output_len) {
    heatshrink_decoder *hsd = heatshrink_decoder_alloc(256,9,3);
    size_t count = 0;
    size_t sunk = 0;
    size_t polled = 0;

    while (sunk < input_len){
        heatshrink_decoder_sink(hsd,&input_data[sunk],input_len-sunk,&count);
        sunk+= count;
        if (sunk == input_len){
            heatshrink_decoder_finish(hsd);
        }
        HSD_poll_res pres;
        do {
            pres = heatshrink_decoder_poll(hsd, &output_data[polled], output_len - polled, &count);
            polled+=count;
        }
        while(pres == HSDR_POLL_MORE);
        if(sunk == input_len){
            heatshrink_decoder_finish(hsd);
        }
    }
    heatshrink_decoder_free(hsd);
    return polled;

}

void timer_callback(int signum) {
    uint8_t decompress_result[1540];

    for(int i = 0; i < packets; i++) {
        char *buf;
        size_t len;
        size_t output_size = heatshrink_decompression(payload[i], input_data[i], decompress_result, 1540);
        size_t bytes_read = 0;
        struct cbor_decoder_result decode_result;
        struct cbor_load_result load_result;
        cbor_item_t* check_cbor = cbor_load(decompress_result, output_size,&load_result);
    
        if (load_result.error.code != CBOR_ERR_NONE) {
            printf(
            "There was an error while reading the input near byte %zu (read %zu "
            "bytes in total): ",
            load_result.error.position, load_result.read);
            continue;
            }
        fflush(stdout);
        cbor_decref(&check_cbor);
    
        FILE *stream;
        stream = open_memstream(&buf,&len);
        if (stream == NULL){
            printf("memstream error\n");
        }
        printf("Length of cbor seq: %ld\n", output_size);
        while (bytes_read < output_size){
            decode_result = cbor_stream_decode(decompress_result+bytes_read,output_size - bytes_read,&callbacks,stream);	
            bytes_read += decode_result.read;
        }
        firstBrack = true;
        fclose(stream); 
        if((fp = fopen("cbor.csv", "a+")) == NULL){
            printf("error opening file");
        }
        fprintf(fp,"%s",buf);
        free(buf);
        len = 0;
        miscInfo = 0;
        fclose(fp);
    }
    packets = 0;
    kymmenekset = 0;

    return;
}

void add_to_confirmed(uint16_t *x,uint8_t msg_id){
    *x = *x | (1u << msg_id);
}

void post_example_handler(coap_resource_t *resource COAP_UNUSED,
                          coap_session_t *session COAP_UNUSED,
                          const coap_pdu_t *request,
                          const coap_string_t *query COAP_UNUSED,
                          coap_pdu_t *response) {
    size_t size;
    const uint8_t *data;
    size_t offset;
    size_t total;
    size_t llen = 0;
    int err = 0;

    coap_bin_const_t token = coap_pdu_get_token(request);
    coap_pdu_type_t msg_type = coap_pdu_get_type(request);
    printf("msg_type: %d msg id : %d\n", msg_type, *token.s);
    uint8_t msg_id = *token.s;
    add_to_confirmed(&confirm_payload.num, msg_id - (kymmenekset * 10));

    if(coap_get_data(request,&llen,&data) == 0){
        printf("data get err \n");
    }
  
    memcpy(payload[msg_id],data,llen);
    input_data[msg_id] = llen;
    packets++;
  
    if(msg_type == COAP_MESSAGE_CON) {
        if(confirm_payload.num == 1023) {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
            confirm_payload.num = 0;
            kymmenekset++;
        }
        else {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
            coap_add_data(response, sizeof(confirm_payload.bytes),confirm_payload.bytes);
        }
        alarm(10);
    }
}


static const coap_bin_const_t *verify_id_callback(coap_bin_const_t *identity, coap_session_t *c_session, void *arg COAP_UNUSED) {
    static coap_bin_const_t psk_key;
    const coap_bin_const_t *s_psk_hint = coap_session_get_psk_hint(c_session);
    const coap_bin_const_t *s_psk_key;
    size_t i;

    coap_log_info("Identity '%.*s' requested, current hint '%.*s'\n", (int)identity->length,
            identity->s,
            s_psk_hint ? (int)s_psk_hint->length : 0,
            s_psk_hint ? (const char *)s_psk_hint->s : "");
    /* Just use the defined key for now */
    psk_key.s = psk;
    psk_key.length = psk_len;
    return &psk_key;
}

static const coap_dtls_spsk_info_t *verify_psk_sni_callback(const char *sni, coap_session_t *c_session COAP_UNUSED, void *arg COAP_UNUSED) {
    static coap_dtls_spsk_info_t psk_info;
    memset(&psk_info, 0, sizeof(psk_info));
    psk_info.hint.s = (const uint8_t *)hint;
    psk_info.hint.length = hint ? strlen(hint) : 0;
    psk_info.key.s = psk;
    psk_info.key.length = 16;
    if (sni) {
        size_t i;
        coap_log_info("SNI '%s' requested\n", sni);
        for (i = 0; i < valid_psk_snis.count; i++) {
            if (strcasecmp(sni, valid_psk_snis.psk_sni_list[i].sni_match) == 0) {
                coap_log_info("Switching to using '%.*s' hint + '%.*s' key\n",
                            (int)valid_psk_snis.psk_sni_list[i].new_hint->length,
                            valid_psk_snis.psk_sni_list[i].new_hint->s,
                            (int)valid_psk_snis.psk_sni_list[i].new_key->length,
                            valid_psk_snis.psk_sni_list[i].new_key->s);
                psk_info.hint = *valid_psk_snis.psk_sni_list[i].new_hint;
                psk_info.key = *valid_psk_snis.psk_sni_list[i].new_key;
                break;
            }
        }
    } else {
        coap_log_debug("SNI not requested\n");
    }
    return &psk_info;
}

static coap_dtls_spsk_t* setup_spsk(void) {
    static coap_dtls_spsk_t dtls_spsk;
    memset(&dtls_spsk, 0, sizeof(dtls_spsk));
    dtls_spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;
    dtls_spsk.validate_id_call_back = valid_ids.count ? verify_id_callback : NULL;
    dtls_spsk.validate_sni_call_back = valid_psk_snis.count ? verify_psk_sni_callback : NULL;
    dtls_spsk.psk_info.hint.s = (const uint8_t *)hint;
    dtls_spsk.psk_info.hint.length = hint ? strlen(hint) : 0;
    dtls_spsk.psk_info.key.s = psk;
    dtls_spsk.psk_info.key.length = 16;
    return &dtls_spsk;
}



int main(){
    coap_set_log_level(LOG_DEBUG);
    coap_dtls_set_log_level(LOG_DEBUG);
    signal(SIGALRM, timer_callback);
    callbacks = cbor_empty_callbacks;
    cbor_setcallbacks(callbacks);
    coap_context_t *ctx = NULL;
    coap_address_t dst;
    int result = EXIT_FAILURE;
    uint16_t cache_ignore_options[] = { COAP_OPTION_BLOCK1,
                                        COAP_OPTION_BLOCK2,
                                        COAP_OPTION_MAXAGE,
                                        COAP_OPTION_IF_NONE_MATCH };

    coap_startup();

    if (resolve_address("192.168.0.199", "5684", &dst) < 0){
        coap_log(LOG_CRIT, "failed to resolve address\n");
        goto end;
    }

    ctx = coap_new_context(NULL);
    coap_context_set_block_mode(ctx, COAP_BLOCK_USE_LIBCOAP);
    coap_cache_ignore_options(ctx, cache_ignore_options, sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));

    coap_dtls_spsk_t *dtls_psk = setup_spsk();

    if (!coap_context_set_psk2(ctx, dtls_psk)) {
        coap_log_info("Unable to set up PSK\n");
    }

    coap_endpoint_t *endpoint = coap_new_endpoint(ctx, &dst, COAP_PROTO_DTLS);
    if (!ctx || !endpoint){
        coap_log(LOG_EMERG, "cannot initialize context\n");
        goto end;
    }
    
    coap_context_set_session_timeout(ctx, 5000);
    coap_resource_t *resource = coap_resource_init(coap_make_str_const("cbor"), 0);
    coap_register_handler(resource, COAP_REQUEST_POST, post_example_handler);
    coap_add_resource(ctx, resource);

    while (1){
        coap_io_process(ctx, COAP_IO_WAIT);
    }

    result = EXIT_SUCCESS;
    end:
    coap_free_context(ctx);
    coap_cleanup();

    return result;
}

