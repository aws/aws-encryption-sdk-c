#include <openssl/ec.h>

void ec_key_nondet_init(EC_KEY* key);

int ec_key_get_reference_count(EC_KEY* key);

void ec_key_unconditional_free(EC_KEY* key);
