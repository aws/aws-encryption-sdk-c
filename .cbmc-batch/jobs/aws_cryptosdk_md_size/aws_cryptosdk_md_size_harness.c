#include <aws/cryptosdk/private/cipher.h>

void harness() {
    /* arguments */
    enum aws_cryptosdk_md_alg md_alg;

    /* operation under verification */
    aws_cryptosdk_md_size(md_alg);
}
