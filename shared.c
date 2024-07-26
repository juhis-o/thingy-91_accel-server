
#include <netdb.h>
#include <arpa/inet.h>
#include "coap3/coap.h"
#include "shared.h"
#include <stdint.h>

uint8_t psk[] = {37,2,175,251,203,52,124,61,205,239,68,126,145,110,216,204};
uint8_t psk_len = 16;

int resolve_address(const char *host, const char *port, coap_address_t *address){
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    int error;

    memset(&hints, 0, sizeof(hints));
    memset(address, 0, sizeof(*address));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(host, port, &hints, &res);
    if (error != 0)
    {
        return error;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next)
    {
        switch (ainfo->ai_family)
        {
            case AF_INET6:
            case AF_INET:
                address->size = ainfo->ai_addrlen;
                memcpy(&address->addr.sin6, ainfo->ai_addr, address->size);
                break;
            default:
                return -1;

        }
    }

    freeaddrinfo(res);
    return 0;
}
