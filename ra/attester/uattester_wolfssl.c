#include "uattester_internal.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/coding.h"

/**
 * @return Length of base64 encoded data including terminating NUL-byte.
 */
void base64_encode
(
    const uint8_t *in,
    uint32_t in_len,
    uint8_t* out,
    uint32_t* out_len /* in/out */
)
{
    // + 1 to account for the terminating \0.
    assert(*out_len >= (in_len + 3 - 1) / 3 * 4 + 1);
    memset(out, 0, *out_len);

    int ret = Base64_Encode_NoNl(in, in_len, out, out_len);
    assert(ret == 0);
    // No need append terminating \0 since we memset() the whole
    // buffer in the beginning.
    *out_len += 1;
}
