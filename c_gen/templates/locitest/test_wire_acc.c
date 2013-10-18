:: include('_copyright.c')

#include <locitest/test_common.h>
#include <loci/of_wire_buf.h>

/**
 * Test low level wire accessor functions
 *
 * This was put in place to test unaligned bit access functions
 */


/* Free function that does nothing for "bind" allocs */
static void unbind_free(void *buf) { }

/* Test data for unaligned get */
typedef struct unaligned_get_test_data_s {
    uint8_t buf[5];
    int bit_offset;
    int bit_width;
    uint32_t expected_value;
} unaligned_get_test_data_t;

/* Many test cases are algorithmically generated. */
static unaligned_get_test_data_t get_test_data[] = {
    {{0x80, 0x02, 0, 0, 0}, 4, 8, 0x28},
    {{0x80, 0x02, 0, 0, 0}, 2, 16, 0x80 >> 2 | 0x02 << 6},
    /* @todo Add more cases */
};

static uint8_t zero_buf[5] = {0, 0, 0, 0, 0};
static uint8_t zebra_buf[5] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

typedef struct zebra_test_cases_s {
    int width;
    int even; /* Expected value for even start bit_offset */
    int odd; /* Expected value for odd start bit_offset */
} zebra_test_cases_t;

static zebra_test_cases_t zebra_test_cases[] = {
    {1, 0, 1},
    {2, 2, 1},
    {3, 2, 5},
    {7, 0x2a, 0x55},
    {8, 0xaa, 0x55},
    {9, 0xaa, 0x155},
    {15, 0x2aaa, 0x5555},
    {16, 0xaaaa, 0x5555},
    {17, 0xaaaa, 0x15555},
    {31, 0x2aaaaaaa, 0x55555555},
    {32, 0xaaaaaaaa, 0x55555555},
};

/* Test 0 value gets for all widths, bit_offsets */
static int
test_zero_value_get(void)
{
    of_wire_buffer_t *wbuf;
    uint32_t val32;
    int bit_offset, width;

    wbuf = of_wire_buffer_new_bind(zero_buf, 5, unbind_free);
    TEST_ASSERT(wbuf != NULL);
    for (bit_offset = 0; bit_offset < 8; bit_offset++) {
        for (width = 1; width < 32; width++) {
            of_wire_buffer_field_get(wbuf, 0, bit_offset, width, &val32);
            TEST_ASSERT(val32 == 0);
        }
    }
    of_wire_buffer_free(wbuf);
    wbuf = NULL;

    return TEST_PASS;
}

/* Test zebra patterns (10) */
static int
test_zebra_value_get(void)
{
    of_wire_buffer_t *wbuf;
    uint32_t val32, expected_val;
    int idx;
    int bit_offset;

    wbuf = of_wire_buffer_new_bind(zebra_buf, 5, unbind_free);
    TEST_ASSERT(wbuf != NULL);
    for (idx = 0; idx < sizeof(zebra_test_cases)/sizeof(zebra_test_cases[0]);
         idx++) {

        for (bit_offset = 0; bit_offset < 8; bit_offset++) {
            of_wire_buffer_field_get(wbuf, 0,
                                     bit_offset,
                                     zebra_test_cases[idx].width,
                                     &val32);
            expected_val = (bit_offset % 2 ?
                            zebra_test_cases[idx].odd : 
                            zebra_test_cases[idx].even);
            TEST_ASSERT(val32 == expected_val);
        }
    }
    of_wire_buffer_free(wbuf);
    wbuf = NULL;

    return TEST_PASS;
}

static int
test_general_value_get(void)
{
    of_wire_buffer_t *wbuf;
    uint32_t val32;
    int idx;

    /* Special cases */
    for (idx = 0; idx < sizeof(get_test_data)/sizeof(get_test_data[0]); idx++) {
        wbuf = of_wire_buffer_new_bind(get_test_data[idx].buf, 5, unbind_free);
        TEST_ASSERT(wbuf != NULL);
        of_wire_buffer_field_get(wbuf, 0,
                                 get_test_data[idx].bit_offset,
                                 get_test_data[idx].bit_width,
                                 &val32);
        TEST_ASSERT(val32 == get_test_data[idx].expected_value);
        of_wire_buffer_free(wbuf);
        wbuf = NULL;
    }

    return TEST_PASS;
}

#if 0

/* Test data for unaligned get */
typedef struct unaligned_set_test_data_s {
    uint8_t buf[5];
    int bit_offset;
    int bit_width;
    uint32_t value;
    uint8_t expected[5];
} unaligned_get_test_data_t;

/* Many test cases are algorithmically generated. */
static unaligned_set_test_data_t set_test_data[] = {
    {{0, 0, 0, 0, 0}, 0, 1, 1, {1, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0}, 1, 1, 1, {2, 0, 0, 0, 0}},

    {{0, 0, 0, 0, 0}, 0, 2, 1, {1, 0, 0, 0, 0}},

    {{0, 0, 0, 0, 0}, 0, 2, 2, {2, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0}, 1, 2, 2, {4, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0}, 0, 2, 2, {2, 0, 0, 0, 0}},

    {{0x80, 0x02, 0, 0, 0}, 2, 16, 0x80 >> 2 | 0x02 << 6},
    /* @todo Add more cases */
};

static uint8_t scratch[5];
#define ZERO_SCRATCH memzero(scratch, sizeof(scratch))

static void
check_set_value(int bit_offset, int bit_width, uint32_t value, uint8_t *expected)
{
    ZERO_SCRATCH;
    wbuf = of_wire_buffer_new_bind(scratch, 5, unbind_free);
    of_wire_buffer_field_set(wbuf, 0, bit_offset, bit_width, value);
    TEST_ASSERT(memcmp(wbuf->buf, expected, 5) == 0);
    of_wire_buffer_free(wbuf);
}


static int
test_shifting_1_set(void)
{
    uint32_t val32 = 1;
    
    /* Shift n-bits of ones thru offset 0 to 7 */
    for (bit_width = 1; bit_width <= 32; bit_width++) {
        val32 = (1 << bit_width) - 1;
        for (bit_offset = 0; bit_offset < 7; bit_offset++) {
            for (byte = 0; byte < 4; byte++) {
                expected[byte] = (val32 << bit_offset) >> (8 * byte);
            }
        }
    }

    /* Now shift 2 bit field through 7 bits of offset */


    /* Shift 1 thru 31 bits and set value */
    for (val32 = 1; val32; val32 <<= 1) {
        ZERO_SCRATCH;
        wbuf = of_wire_buffer_new_bind(scratch, 5, unbind_free);
        of_wire_buffer_field_set(wbuf, 0, 0, , 
                                     of_wire_buffer_free(wbuf);
        
    }

}

static int
test_general_value_set(void)
{
    of_wire_buffer_t *wbuf;
    uint32_t val32;
    int idx;

    /* Special cases */
    for (idx = 0; idx < sizeof(set_test_data)/sizeof(set_test_data[0]); idx++) {
        wbuf = of_wire_buffer_new_bind(set_test_data[idx].buf, 5, unbind_free);
        TEST_ASSERT(wbuf != NULL);
        of_wire_buffer_field_set(wbuf, 0,
                                 set_test_data[idx].bit_offset,
                                 set_test_data[idx].bit_width,
                                 set_test_data[idx].value);
        TEST_ASSERT(memcmp(set_test_data[idx].expected, wbuf->buf, 5) == 0);
        of_wire_buffer_free(wbuf);
        wbuf = NULL;
    }

    return TEST_PASS;
}
#endif

int
run_buffer_accessor_tests(void)
{
    RUN_TEST(zero_value_get);
    RUN_TEST(zebra_value_get);
    RUN_TEST(general_value_get);

    return TEST_PASS;
}

