#include <aws/cryptosdk/private/header.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <sys/mman.h>
#endif

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
    //iv len
    0x0c, 
    //frame length
    0x00,  0x00,  0x10,  0x00, 
    //iv  FIXME: this IV and authentication tag is not valid, change when we implement authentication
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

uint8_t test_header_1_auth_tag_arr[] =
{0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef};

struct aws_cryptosdk_hdr test_header_1_hdr = {
    .alg_id = AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256,
    .aad_count = sizeof(test_header_1_aad_tbl)/sizeof(struct aws_cryptosdk_hdr_aad),
    .edk_count = sizeof(test_header_1_edk_tbl)/sizeof(struct aws_cryptosdk_hdr_edk),
    .frame_len = 0x1000,
    .iv = {.buffer = test_header_1_iv_arr, .len = sizeof(test_header_1_iv_arr)},
    .auth_tag = {.buffer = test_header_1_auth_tag_arr, .len = sizeof(test_header_1_auth_tag_arr)},
    .message_id_arr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
    .message_id = {.buffer = test_header_1_hdr.message_id_arr, .len = sizeof(test_header_1_hdr.message_id_arr)},
    .aad_tbl = test_header_1_aad_tbl,
    .edk_tbl = test_header_1_edk_tbl
};

int simple_header_parse() {
    struct aws_allocator * allocator = aws_default_allocator();
    struct aws_cryptosdk_hdr hdr;


    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
                       aws_cryptosdk_hdr_parse(allocator, &hdr, test_header_1, sizeof(test_header_1) - 1));

    // Known answer tests
    TEST_ASSERT_INT_EQ(hdr.alg_id, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256);

    TEST_ASSERT_BUF_EQ(hdr.message_id,
        0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88
    );

    TEST_ASSERT_BUF_EQ(hdr.iv,
        0x00,  0x01,  0x02,  0x03,  0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b
    );

    TEST_ASSERT_BUF_EQ(hdr.auth_tag,
        0xde,  0xad,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0x00,  0xbe, 0xef
    );

    // Misc values
    TEST_ASSERT_INT_EQ(2, hdr.aad_count);
    TEST_ASSERT_INT_EQ(3, hdr.edk_count);
    TEST_ASSERT_INT_EQ(0x1000, hdr.frame_len);

    // AAD checks
    TEST_ASSERT_BUF_EQ(hdr.aad_tbl[0].key, 0x01, 0x02, 0x03, 0x04);
    TEST_ASSERT_BUF_EQ(hdr.aad_tbl[0].value, 0x01, 0x00, 0x01, 0x00, 0x01);

    TEST_ASSERT_INT_EQ(0, hdr.aad_tbl[1].key.len);
    TEST_ASSERT_INT_EQ(0, hdr.aad_tbl[1].value.len);

    // EDK checks
    TEST_ASSERT_INT_EQ(0, hdr.edk_tbl[0].provider_id.len);
    TEST_ASSERT_INT_EQ(0, hdr.edk_tbl[0].provider_info.len);
    TEST_ASSERT_INT_EQ(0, hdr.edk_tbl[0].enc_data_key.len);

    TEST_ASSERT_INT_EQ(0, hdr.edk_tbl[2].provider_id.len);
    TEST_ASSERT_INT_EQ(0, hdr.edk_tbl[2].provider_info.len);
    TEST_ASSERT_INT_EQ(0, hdr.edk_tbl[2].enc_data_key.len);

    TEST_ASSERT_BUF_EQ(hdr.edk_tbl[1].provider_id, 0x10, 0x11, 0x12, 0x00);
    TEST_ASSERT_BUF_EQ(hdr.edk_tbl[1].provider_info, 0x01, 0x02, 0x03, 0x04);
    TEST_ASSERT_BUF_EQ(hdr.edk_tbl[1].enc_data_key, 0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88);

    aws_cryptosdk_hdr_free(allocator, &hdr);
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
    size_t offset = -inlen % pagesize;
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

    struct aws_allocator * allocator = aws_default_allocator();

    struct aws_cryptosdk_hdr hdr;
    // We don't care about the return value as long as we don't actually crash.
    aws_cryptosdk_hdr_parse(allocator, &hdr, phdr, inlen);

    // This is only necessary when aws_cryptosdk_hdr_parse succeeds,
    // but including it all the time is also a good test that we have made
    // aws_cryptosdk_hdr_free idempotent.
    aws_cryptosdk_hdr_free(allocator, &hdr);
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
    printf("\nWarning: overread test cannot be performed on this system. Passing trivially.\n");
    return 0; // can't do overread tests portably
}
#endif

int header_size() {
    size_t bytes_needed;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_size(&test_header_1_hdr, &bytes_needed));
    TEST_ASSERT_INT_EQ(bytes_needed, sizeof(test_header_1) - 1);

    return 0;
}

int header_write() {
    size_t outlen = sizeof(test_header_1) - 1; // not including junk byte
    uint8_t outbuf[outlen];
    size_t bytes_written;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_write(&test_header_1_hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, outlen);
    TEST_ASSERT(!memcmp(test_header_1, outbuf, outlen));

    return 0;
}

struct test_case header_test_cases[] = {
    { "header", "parse", simple_header_parse },
    { "header", "overread", overread_test },
    { "header", "size", header_size },
    { "header", "write", header_write },
    { NULL }
};
