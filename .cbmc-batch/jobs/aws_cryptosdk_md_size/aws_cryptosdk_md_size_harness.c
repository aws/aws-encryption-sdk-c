#include <aws/cryptosdk/private/cipher.h>

void harness() {
    /* arguments */
    enum aws_cryptosdk_md_alg md_alg;

    /* operation under verification */
    size_t size = aws_cryptosdk_md_size(md_alg);

    /* assertions */
    if (md_alg == AWS_CRYPTOSDK_MD_SHA512) {
        assert(size == (512 / 8));
    } else {
        assert(size == 0);
    }
}
