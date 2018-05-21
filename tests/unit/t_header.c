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
struct aws_cryptosdk_edk test_header_1_edk_tbl[] = {
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
    .edk_count = sizeof(test_header_1_edk_tbl)/sizeof(struct aws_cryptosdk_edk),
    .frame_len = 0x1000,
    .iv = {.buffer = test_header_1_iv_arr, .len = sizeof(test_header_1_iv_arr)},
    .auth_tag = {.buffer = test_header_1_auth_tag_arr, .len = sizeof(test_header_1_auth_tag_arr)},
    .message_id = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
    .aad_tbl = test_header_1_aad_tbl,
    .edk_tbl = test_header_1_edk_tbl,
    .auth_len = sizeof(test_header_1) - 29 // not used by aws_cryptosdk_hdr_size/write
};

static const uint8_t test_header_2[] = { // same as test_header_1 with no AAD section
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (0 bytes)
    0x00, 0x00,
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

static const uint8_t bad_header_1[] = { // nonzero reserve bytes
    //version, type, alg ID
    0x01,  0x80,  0x02,  0x14,
    //message ID
    0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,  0x11,  0x22,  0x33,  0x44,  0x55,  0x66,  0x77,  0x88,
    //AAD length (0 bytes)
    0x00, 0x00,
    //edk count
    0x00, 0x00,
    //content type
    0x02,
    //reserved
    0x00,  0x00,  0x00,  0x01,
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

struct aws_cryptosdk_hdr test_header_2_hdr = {
    .alg_id = AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256,
    .aad_count = 0,
    .edk_count = sizeof(test_header_1_edk_tbl)/sizeof(struct aws_cryptosdk_edk),
    .frame_len = 0x1000,
    .iv = {.buffer = test_header_1_iv_arr, .len = sizeof(test_header_1_iv_arr)},
    .auth_tag = {.buffer = test_header_1_auth_tag_arr, .len = sizeof(test_header_1_auth_tag_arr)},
    .message_id = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
    .aad_tbl = NULL,
    .edk_tbl = test_header_1_edk_tbl,
    .auth_len = sizeof(test_header_2) - 29 // not used by aws_cryptosdk_hdr_size/write
};


int simple_header_parse() {
    struct aws_allocator * allocator = aws_default_allocator();
    struct aws_cryptosdk_hdr hdr;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
                       aws_cryptosdk_hdr_parse(allocator, &hdr, test_header_1, sizeof(test_header_1) - 1));

    // Known answer tests
    TEST_ASSERT_INT_EQ(hdr.alg_id, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256);

    struct aws_byte_cursor message_id = {.ptr = hdr.message_id, .len = MESSAGE_ID_LEN};
    TEST_ASSERT_CUR_EQ(message_id,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    );

    TEST_ASSERT_BUF_EQ(hdr.iv,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    );

    TEST_ASSERT_BUF_EQ(hdr.auth_tag,
        0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef
    );

    // Misc values
    TEST_ASSERT_INT_EQ(2, hdr.aad_count);
    TEST_ASSERT_INT_EQ(3, hdr.edk_count);
    TEST_ASSERT_INT_EQ(0x1000, hdr.frame_len);
    TEST_ASSERT_INT_EQ(hdr.auth_len, sizeof(test_header_1) - 29); // 1 junk byte, 12 IV bytes, 16 auth tag bytes

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

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), hdr.auth_len + hdr.auth_tag.len + hdr.iv.len);

    aws_cryptosdk_hdr_free(allocator, &hdr);
    return 0;
}

int simple_header_parse2() {
    struct aws_allocator * allocator = aws_default_allocator();
    struct aws_cryptosdk_hdr hdr;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS,
                       aws_cryptosdk_hdr_parse(allocator, &hdr, test_header_2, sizeof(test_header_2)));

    // Known answer tests
    TEST_ASSERT_INT_EQ(hdr.alg_id, AES_128_GCM_IV12_AUTH16_KDSHA256_SIGEC256);

    struct aws_byte_cursor message_id = {.ptr = hdr.message_id, .len = MESSAGE_ID_LEN};
    TEST_ASSERT_CUR_EQ(message_id,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    );

    TEST_ASSERT_BUF_EQ(hdr.iv,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    );

    TEST_ASSERT_BUF_EQ(hdr.auth_tag,
        0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef
    );

    // Misc values
    TEST_ASSERT_INT_EQ(0, hdr.aad_count);
    TEST_ASSERT_INT_EQ(3, hdr.edk_count);
    TEST_ASSERT_INT_EQ(0x1000, hdr.frame_len);
    TEST_ASSERT_INT_EQ(hdr.auth_len, sizeof(test_header_2) - 29); // 1 junk byte, 12 IV bytes, 16 auth tag bytes

    TEST_ASSERT_ADDR_EQ(hdr.aad_tbl, NULL);

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

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), hdr.auth_len + hdr.auth_tag.len + hdr.iv.len);

    aws_cryptosdk_hdr_free(allocator, &hdr);
    return 0;
}


int failed_parse() {
    struct aws_allocator * allocator = aws_default_allocator();

    // incomplete header
    struct aws_cryptosdk_hdr hdr;
    TEST_ASSERT_INT_NE(AWS_OP_SUCCESS,
                       aws_cryptosdk_hdr_parse(allocator, &hdr, test_header_1, sizeof(test_header_1) - 5));

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr), 0);

    // faulty header
    struct aws_cryptosdk_hdr hdr2;
    TEST_ASSERT_INT_NE(AWS_OP_SUCCESS,
                       aws_cryptosdk_hdr_parse(allocator, &hdr2, bad_header_1, sizeof(bad_header_1)));

    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&hdr2), 0);

    return 0;
}

#ifdef _POSIX_VERSION
// Returns the amount of padding needed to align len to a multiple of
// the system page size.
static size_t page_padding(size_t len) {
    size_t pagesize = sysconf(_SC_PAGESIZE);
    return -len % pagesize;
}

// Tests that we don't overread past the end of the buffer.
// Optionally (if flip_bit_index >= 0 && < inlen * 8), flips a bit in the header buffer.
static void overread_once(const uint8_t *inbuf, size_t inlen, ssize_t flip_bit_index) {
    // Copy the header to a buffer aligned at the end of a page, and just before the subsequent page

    // First, round up to at least size + one page, page aligned.
    int pagesize = sysconf(_SC_PAGESIZE);
    size_t offset = page_padding(inlen);
    size_t total_size = offset + inlen + pagesize;

    // We now set up a memory layout looking like the following:
    // [padding] [header] [inaccessible page]
    uint8_t *pbuffer = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

    int byte_offset = flip_bit_index >> 3;
    if (flip_bit_index >= 0 && byte_offset < inlen) {
        int bit_offset = flip_bit_index & 7;
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

static int overread() {
    // Test that various truncations don't result in an overread
    for (size_t hdrlen = 0; hdrlen < sizeof(test_header_1); hdrlen++) {
        overread_once(test_header_1, hdrlen, -1);
    }

    // Test that corrupt header fields don't result in an overread
    for (size_t flipbit = 0; flipbit < sizeof(test_header_1) << 3; flipbit++) {
        overread_once(test_header_1, sizeof(test_header_1), flipbit);
    }
    return 0;
}

#else // _POSIX_VERSION
static int overread() {
    printf("\nWarning: overread test cannot be performed on this system. Passing trivially.\n");
    return 0; // can't do overread tests portably
}
#endif

int header_size() {
    TEST_ASSERT_INT_EQ(aws_cryptosdk_hdr_size(&test_header_1_hdr), sizeof(test_header_1) - 1);

    return 0;
}

int simple_header_write() {
    size_t outlen = sizeof(test_header_1) - 1; // not including junk byte
    uint8_t outbuf[outlen];
    size_t bytes_written;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_write(&test_header_1_hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, outlen);
    TEST_ASSERT(!memcmp(test_header_1, outbuf, outlen));

    size_t outlen2 = sizeof(test_header_2) - 1;
    uint8_t outbuf2[outlen2];
    size_t bytes_written2;

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_hdr_write(&test_header_2_hdr, &bytes_written2, outbuf2, outlen2));
    TEST_ASSERT_INT_EQ(bytes_written2, outlen2);
    TEST_ASSERT(!memcmp(test_header_2, outbuf2, outlen2));

    return 0;
}

int header_failed_write() {
    size_t outlen = sizeof(test_header_1) - 2;
    uint8_t outbuf[outlen];
    size_t bytes_written;
    memset(outbuf, 'A', outlen);

    TEST_ASSERT_INT_NE(AWS_OP_SUCCESS, aws_cryptosdk_hdr_write(&test_header_1_hdr, &bytes_written, outbuf, outlen));
    TEST_ASSERT_INT_EQ(bytes_written, 0);
    for (size_t idx = 0 ; idx < outlen ; ++idx) {
        TEST_ASSERT_INT_EQ(outbuf[idx], 0);
    }

    return 0;
}

int overwrite() {

    struct aws_cryptosdk_hdr * test_headers[] = {&test_header_1_hdr, &test_header_2_hdr};
    int pagesize = sysconf(_SC_PAGESIZE);

    for (int idx = 0 ; idx < sizeof(test_headers)/sizeof(struct aws_cryptosdk_hdr *) ; ++idx) {
        size_t bytes_written;

        int header_len = aws_cryptosdk_hdr_size(test_headers[idx]);

        // First, round up to at least size + one page, page aligned.
        size_t offset = page_padding(header_len);
        size_t total_size = offset + header_len + pagesize;

        // We now set up a memory layout looking like the following:
        // [padding] [header] [inaccessible page]
        uint8_t *pbuffer = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pbuffer == MAP_FAILED) {
            perror("mmap");
            abort();
        }

        uint8_t *phdr = pbuffer + offset;
        uint8_t *ptrap = phdr + header_len;

        if (mprotect(ptrap, pagesize, PROT_NONE)) {
            perror("mprotect");
            abort();
        }

        aws_cryptosdk_hdr_write(test_headers[idx], &bytes_written, phdr, header_len + pagesize);
        munmap(pbuffer, total_size);
    }
    return 0;
}

struct test_case header_test_cases[] = {
    { "header", "parse", simple_header_parse },
    { "header", "parse2", simple_header_parse2 },
    { "header", "failed_parse", failed_parse },
    { "header", "overread", overread },
    { "header", "size", header_size },
    { "header", "write", simple_header_write },
    { "header", "failed_write", header_failed_write },
    { "header", "overwrite", overwrite },
    { NULL }
};
