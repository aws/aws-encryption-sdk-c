#include <openssl/ossl_typ.h>

#define NID_undef 0

/** Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
  /** the point is encoded as z||x, where the octet z specifies
   *  which solution of the quadratic equation y is  */
  POINT_CONVERSION_COMPRESSED = 2,
  /** the point is encoded as z||x||y, where z is the octet 0x04  */
  POINT_CONVERSION_UNCOMPRESSED = 4,
  /** the point is encoded as z||x||y, where the octet z specifies
   *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef struct ec_group_st EC_GROUP;

struct ECDSA_SIG_st {
  BIGNUM *r;
  BIGNUM *s;
};

typedef struct ECDSA_SIG_st ECDSA_SIG;
