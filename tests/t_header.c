#include <aws/cryptosdk/header.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <sys/mman.h>
#endif


// XXX: proper error checking
#define AWS_ERR_TRUNCATED AWS_OP_ERR
#define AWS_ERR_BAD_ARG AWS_OP_ERR


static const uint8_t test_header_1[] = {
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14, 
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88, 
    //AAD length (19 bytes)
    0x00, 0x13,
    //AAD - kv pair count (2 pairs)
    0x00, 0x02, 
    //key length, key data
    0x00,  0x04, 
    0x01,  0x02,  0x03,  0x04, 
    //value length, value data
    0x00,  0x05, 
    0x01,  0x00,  0x01,  0x00,  0x01, 
    //key length, key data
    0x00,  0x00, 
    //val length, val data
    0x00,  0x00, 
// p = 49 bytes
    //edk count
    0x00, 0x03, 
    //edk #0 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 
    //edk #1
    //provider ID len + data
    0x00,  0x04,  0x10,  0x11,  0x12,  0x00, 
    //prov info len + data
    0x00,  0x04,  0x01,  0x02,  0x03,  0x04, 
    //encrypted data key
    0x00,  0x08,  0x11,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x88,
    //edk #2 (all empty fields)
    0x00,  0x00,  0x00,  0x00,  0x00,  0x00, 

    //content type
    0x02, 

    //reserved
    0x00,  0x00,  0x00,  0x00, 
    //ivlen
    0x0c, 
    //frame length
    0x00,  0x00,  0x10,  0x00, 
    //iv  FIXME: this IV and authentication tag is not valid
    0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,
    //header auth
    0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef,
    // extra byte - used to verify that we can parse with extra trailing junk
    0xFF
};

uint8_t test_header_1_aad_key[] = {0x01, 0x02, 0x03, 0x04};
uint8_t test_header_1_aad_value[] = {0x01, 0x00, 0x01, 0x00, 0x01};
struct aws_cryptosdk_hdr_aad test_header_1_aad_tbl[] = {
    {
        .key = {.len = sizeof(test_header_1_aad_key), .buffer = test_header_1_aad_key},
        .value = {.len = sizeof(test_header_1_aad_value), .buffer = test_header_1_aad_value}
    },
    {0}
};

uint8_t test_header_1_edk_provider_id[] = {0x10, 0x11, 0x12, 0x00};
uint8_t test_header_1_edk_provider_info[] = {0x01, 0x02, 0x03, 0x04};
uint8_t test_header_1_edk_enc_data_key[] = {0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88};
struct aws_cryptosdk_hdr_edk test_header_1_edk_tbl[] = {
    {0},
    {
        .provider_id = {.len = sizeof(test_header_1_edk_provider_id), .buffer = test_header_1_edk_provider_id},
        .provider_info = {.len = sizeof(test_header_1_edk_provider_info), .buffer = test_header_1_edk_provider_info},
        .enc_data_key = {.len = sizeof(test_header_1_edk_enc_data_key), .buffer = test_header_1_edk_enc_data_key}
    },
    {0}
};

uint8_t test_header_1_iv_arr[] =
{0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b};
struct aws_byte_buf test_header_1_iv = {.len = sizeof(test_header_1_iv_arr), .buffer=test_header_1_iv_arr};

uint8_t test_header_1_auth_tag_arr[] =
{0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef};
struct aws_byte_buf test_header_1_auth_tag = {.len = sizeof(test_header_1_auth_tag_arr), .buffer=test_header_1_auth_tag_arr};

uint8_t test_header_1_message_id[] =
{0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88};


/**
 * Performs a simple known-answer test on the header preparsing logic.
 */
int simple_header_preparse() {
    size_t header_space_needed = 0, header_length = 0;

    for (size_t size = 60; size < sizeof(test_header_1) - 2; size++) {
        TEST_ASSERT_INT_EQ(AWS_ERR_TRUNCATED, 
            aws_cryptosdk_hdr_preparse(test_header_1, size, &header_space_needed, &header_length));
    }

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
        aws_cryptosdk_hdr_preparse(test_header_1, sizeof(test_header_1) - 1, &header_space_needed, &header_length));

    TEST_ASSERT_INT_EQ(sizeof(test_header_1) - 1, header_length);

    header_length = 0;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
        aws_cryptosdk_hdr_preparse(test_header_1, sizeof(test_header_1), &header_space_needed, &header_length));

    TEST_ASSERT_INT_EQ(sizeof(test_header_1) - 1, header_length);
    
    return 0;
}

int simple_header_parse() {
    size_t header_space_needed = 0, header_length = 0;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
        aws_cryptosdk_hdr_preparse(test_header_1, sizeof(test_header_1) - 1, &header_space_needed, &header_length));

    void *header_buf = malloc(header_space_needed);
    if (!header_buf) {
        abort();
    }

    struct aws_cryptosdk_hdr *hdr;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
        aws_cryptosdk_hdr_parse(&hdr, header_buf, header_space_needed, test_header_1, sizeof(test_header_1) - 1));

    // Known answer tests
    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_get_algorithm(hdr), AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256);

    struct aws_byte_buf buf;

    const uint8_t *ptr;
    size_t size;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_msgid(hdr, &buf));
    TEST_ASSERT_BUF_EQ(buf, 
        0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88
    );

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_iv(hdr, &buf));
    TEST_ASSERT_BUF_EQ(buf,
        0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b
    );

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_authtag(hdr, &buf));
    TEST_ASSERT_BUF_EQ(buf,
        0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef
    );

    // Misc values
    TEST_ASSERT_INT_EQ(2, aws_cryptosdk_hdr_get_aad_count(hdr));
    TEST_ASSERT_INT_EQ(3, aws_cryptosdk_hdr_get_edk_count(hdr));
    TEST_ASSERT_INT_EQ(0x1000, aws_cryptosdk_hdr_get_frame_len(hdr));

    // AAD checks
    struct aws_cryptosdk_hdr_aad aad;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_aad(hdr, 0, &aad));
    TEST_ASSERT_BUF_EQ(aad.key, 0x01, 0x02, 0x03, 0x04);
    TEST_ASSERT_BUF_EQ(aad.value, 0x01, 0x00, 0x01, 0x00, 0x01);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_aad(hdr, 1, &aad));
    TEST_ASSERT_INT_EQ(0, aad.key.len);
    TEST_ASSERT_INT_EQ(0, aad.value.len);

    TEST_ASSERT_INT_EQ(AWS_ERR_BAD_ARG, aws_cryptosdk_hdr_get_aad(hdr, -1, &aad));
    TEST_ASSERT_INT_EQ(AWS_ERR_BAD_ARG, aws_cryptosdk_hdr_get_aad(hdr, 2, &aad));

    // EDK checks
    struct aws_cryptosdk_hdr_edk edk;
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_edk(hdr, 0, &edk));
    TEST_ASSERT_INT_EQ(0, edk.provider_id.len);
    TEST_ASSERT_INT_EQ(0, edk.provider_info.len);
    TEST_ASSERT_INT_EQ(0, edk.enc_data_key.len);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_edk(hdr, 2, &edk));
    TEST_ASSERT_INT_EQ(0, edk.provider_id.len);
    TEST_ASSERT_INT_EQ(0, edk.provider_info.len);
    TEST_ASSERT_INT_EQ(0, edk.enc_data_key.len);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_get_edk(hdr, 1, &edk));
    TEST_ASSERT_BUF_EQ(edk.provider_id,
        0x10, 0x11, 0x12, 0x00
    );
    TEST_ASSERT_BUF_EQ(edk.provider_info,
        0x01,  0x02,  0x03,  0x04
    );
    TEST_ASSERT_BUF_EQ(edk.enc_data_key,
        0x11,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x88
    );

    free(header_buf);
    return 0;
}

#ifdef _POSIX_VERSION
// Tests that we don't overread past the end of the buffer.
// Optionally (if flip_bit_index >= 0 && < inlen * 8), flips a bit in the header buffer.
static void overread_test_once(const uint8_t *inbuf, size_t inlen, ssize_t flip_bit_index) {
    // Copy the header to a buffer aligned at the end of a page, and just before the subsequent page

    // First, round up to at least size + one page, page aligned.
    // This technically will round up too far if inlen is already divisible by page size, but we don't
    // care about efficiency so much.
    int pagesize = sysconf(_SC_PAGESIZE);
    size_t offset = pagesize - (inlen % pagesize);
    size_t total_size = offset + inlen + pagesize;

    // We now set up a memory layout looking like the following:
    // [padding] [header] [inaccessible page]

    uint8_t *pbuffer = mmap(NULL, total_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pbuffer == MAP_FAILED) {
        perror("mmap");
        abort();
    }

    uint8_t *phdr = pbuffer + offset;
    uint8_t *ptrap = phdr + inlen;

    memcpy(phdr, inbuf, inlen);
    if (mprotect(ptrap, pagesize, PROT_NONE)) {
        perror("mprotect");
        abort();
    }

    if (flip_bit_index >= 0 && flip_bit_index < inlen * 8) {
        int byte_offset = flip_bit_index / 8;
        int bit_offset  = flip_bit_index % 8;
        phdr[byte_offset] ^= (1 << bit_offset);
    }

    size_t header_space_needed = 0, header_length = 0;

    if (aws_cryptosdk_hdr_preparse(phdr, inlen, &header_space_needed, &header_length)
            != AWS_OP_SUCCESS) {
        // Preparse failed, probably because our buffer is truncated. This is okay, but we still want to exercise
        // parsing, so make up a huge buffer for it.
        header_space_needed = inlen + 65536;
    }

    void *header_buf = malloc(header_space_needed);
    if (!header_buf) {
        abort();
    }

    struct aws_cryptosdk_hdr *hdr;
    // We don't care about the return value as long as we don't actually crash.
    aws_cryptosdk_hdr_parse(&hdr, header_buf, header_space_needed, phdr, inlen);

    free(header_buf);
    munmap(pbuffer, total_size);
}

static int overread_test() {
    // Test that various truncations don't result in an overread
    for (size_t hdrlen = 0; hdrlen < sizeof(test_header_1); hdrlen++) {
        overread_test_once(test_header_1, hdrlen, -1);
    }

    // Test that corrupt header fields don't result in an overread
    for (size_t flipbit = 0; flipbit <= sizeof(test_header_1) * 8; flipbit++) {
        overread_test_once(test_header_1, sizeof(test_header_1), flipbit);
    }

    return 0;
}

#else // _POSIX_VERSION
static int overread_test() {
    return 0; // can't do overread tests portably
}
#endif

int setup_test_header_1_struct(struct aws_cryptosdk_hdr ** hdr) {
    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_alloc(hdr));

    aws_cryptosdk_hdr_set_algorithm(*hdr, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256);
    aws_cryptosdk_hdr_set_aad_tbl(*hdr, sizeof(test_header_1_aad_tbl)/sizeof(struct aws_cryptosdk_hdr_aad), test_header_1_aad_tbl);
    aws_cryptosdk_hdr_set_edk_tbl(*hdr, sizeof(test_header_1_edk_tbl)/sizeof(struct aws_cryptosdk_hdr_edk), test_header_1_edk_tbl);
    aws_cryptosdk_hdr_set_frame_len(*hdr, 0x1000);
    aws_cryptosdk_hdr_set_iv(*hdr, &test_header_1_iv);
    aws_cryptosdk_hdr_set_authtag(*hdr, &test_header_1_auth_tag);
    aws_cryptosdk_hdr_set_msgid(*hdr, test_header_1_message_id);

    return 0;
}

int header_size() {
    struct aws_cryptosdk_hdr * hdr;
    TEST_ASSERT_INT_EQ(0, setup_test_header_1_struct(&hdr));

    size_t bytes_needed;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_size(hdr, &bytes_needed));
    TEST_ASSERT_INT_EQ(bytes_needed, sizeof(test_header_1) - 1);

    aws_cryptosdk_hdr_free(hdr);
    return 0;
}

int header_write() {
    struct aws_cryptosdk_hdr * hdr;
    TEST_ASSERT_INT_EQ(0, setup_test_header_1_struct(&hdr));

    size_t outlen = sizeof(test_header_1) - 1; // not including junk byte
    uint8_t outbuf[outlen];
    size_t bytes_written;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_write(hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, outlen);
    TEST_ASSERT(!memcmp(test_header_1, outbuf, outlen));

    aws_cryptosdk_hdr_free(hdr);
    return 0;
}

struct test_case header_test_cases[] = {
    { "header", "preparse", simple_header_preparse },
    { "header", "parse", simple_header_parse },
    { "header", "overread", overread_test },
    { "header", "size", header_size },
    { "header", "write", header_write },
    { NULL }
};
