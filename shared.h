#ifndef EXAMPLE_SHARED_H
#define EXAMPLE_SHARED_H
#include <unistd.h>
#define PSK_KEY "2502affbcb347c3dcdef447e916ed8cc"

typedef struct coap_address_t coap_address_t;

typedef struct id_def_t {
  char *hint_match;
  coap_bin_const_t *identity_match;
  coap_bin_const_t *new_key;
} id_def_t;

typedef struct valid_ids_t {
  size_t count;
  id_def_t *id_list;
} valid_ids_t;
static valid_ids_t valid_ids = {0, NULL};

typedef struct psk_sni_def_t {
  char *sni_match;
  coap_bin_const_t *new_key;
  coap_bin_const_t *new_hint;
} psk_sni_def_t;

typedef struct valid_psk_snis_t {
  size_t count;
  psk_sni_def_t *psk_sni_list;
} valid_psk_snis_t;


int resolve_address(const char *host, const char *port, coap_address_t *address);

#endif //EXAMPLE_SHARED_H
