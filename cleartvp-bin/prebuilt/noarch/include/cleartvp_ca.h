#ifndef __CLEARTVP_CA_H__
#define __CLEARTVP_CA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include  <stdint.h>

typedef enum CLEARTVPResult {
        CLEARTVP_SUCCESS = 0,
        CLEARTVP_ERROR_INIT_FAILED,
        CLEARTVP_ERROR_TERMINATE_FAILED,
        CLEARTVP_FAILURE = -1
} CLEARTVPResult;

#define TA_CLEARTVP_UUID {0x41fe9859, 0x71e4,0x4bf4, \
                       {0xbb,0xaa,0xd7,0x14,0x35,0xb1,0x27,0xae}}
///* The TAFs ID implemented in this TA */

enum ta_cleartvp_cmd_id {
        TA_CLEARTVP_CMD_ID_INVALID = 0x0,                       //0
        TA_CLEARTVP_CMD_ID_INIT,
        TA_CLEARTVP_CMD_DECRYPT_AUDIO,
        TA_CLEARTVP_CMD_DECRYPT_VIDEO,
};
unsigned int CLEARTVP_decrypt_audio( uint8_t *srcPtr, uint32_t srclen, uint8_t * dstPtr,uint32_t dstlen);
unsigned int CLEARTVP_decrypt_video( uint8_t *srcPtr, uint32_t srclen, uint32_t outputHandle, uint32_t clear, uint32_t enc);
unsigned int CLEARTVP_Terminate();
#ifdef __cplusplus
}
#endif
#endif

