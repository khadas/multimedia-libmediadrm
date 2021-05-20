/*
 * secmem_types.h
 *
 *Copyright (C) 2020 Amlogic, Inc. All rights reserved.
 *
 *  Created on: 2020年3月30日
 *      Author: tao
 */

#ifndef _SECMEM_TYPES_H_
#define _SECMEM_TYPES_H_

enum {
    SECMEM_V2_MEM_SOURCE_NONE                          = 0,
    SECMEM_V2_MEM_SOURCE_VDEC,
    SECMEM_V2_MEM_SOURCE_CODEC_MM
};

enum {
    SECMEM_TVP_TYPE_NONE                               = 0,
    SECMEM_TVP_TYPE_FHD,
    SECMEM_TVP_TYPE_UHD
};

enum {
    SECMEM_CODEC_DEFAULT                       = 0,
    SECMEM_CODEC_VP9,
    SECMEM_CODEC_AV1,
    SECMEM_CODEC_AUDIO,
};

enum {
    SECMEM_V2_USAGE_DRM_PLAYBACK                       = 0,
    SECMEM_V2_USAGE_CAS_LIVE,
    SECMEM_V2_USAGE_CAS_RECORD,
    SEMEMM_V2_USAGE_CAS_REPLAY
};

enum {
    SECMEM_ERROR_INVALID_SESSION                       = 0x1000,
    SECMEM_ERROR_INVALID_BLOCK,
    SECMEM_ERROR_INVALID_HANDLE,
    SECMEM_ERROR_INVALID_CONFIG,
    SECMEM_ERROR_SESSION_FULL,
    SECMEM_ERROR_BLOCK_FULL,
    SECMEM_ERROR_OUT_OF_MEMORY,
    SECMEM_ERROR_BUFFER_FULL,
    SECMEM_ERROR_BLOCK_NOT_EMPTY,
    SECMEM_ERROR_BLOCK_IS_EMPTY,
    SECMEM_ERROR_INVALID_RESOURCE,
    SECMEM_ERROR_INVALID_OPERATION,
    SECMEM_ERROR_NO_CONTINUOUS_MEMORY,
    SECMEM_ERROR_OPEN_TVP_CHANNEL,
    SECMEM_ERROR_INVALID_AUDIO_CONTENT,
    SECMEM_ERROR_MAX
};

enum {
    PAD_TYPE_H264_END_HEADER                           = 1,
    PAD_TYPE_H265_END,
    PAD_TYPE_VP9_END,
    PAD_TYPE_ALL_ZERO_DATA,
    PAD_TYPE_DV,
};

enum {
    SECMEM_CAS_ID_TEST                                 = 0,
    SECMEM_CAS_ID_MAX
};

enum {
    AUD_VALID_TYPE_NONE                                = 0,
    AUD_VALID_TYPE_MPGAUD,
    AUD_VALID_TYPE_AC3,
    AUD_VALID_TYPE_AAC_ADTS,
    AUD_VALID_TYPE_AAC_LOAS,
    AUD_VALID_TYPE_END,
};

enum {
    STREAM_TYPE_AVCC                                   = 1,
    STREAM_TYPE_AVC2NALU,
    STREAM_TYPE_VP9,
    STREAM_TYPE_HVCC,
    STREAM_TYPE_HVC2NALU,
    STREAM_TYPE_AV1,
};

enum {
    PARSER_H264_SPS_SEEN                               = 1 << 0,
    PARSER_H264_PPS_SEEN                               = 1 << 1,
    PARSER_H264_IDR_SEEN                               = 1 << 2,
    PARSER_H264_SLICE_SEEN                             = 1 << 3,
};

enum {
    PARSER_H265_SPS_SEEN                               = 1 << 0,
    PARSER_H265_PPS_SEEN                               = 1 << 1,
    PARSER_H265_VPS_SEEN                               = 1 << 2,
    PARSER_H265_SLICE_SEEN                             = 1 << 3,
};

enum cas_crypto_mode {
    ALGO_INVALID = -1,
    ALGO_AES_CBC = 0,
    ALGO_AES_CTR = 1,
    ALGO_DVB_CSA2 = 2,
    ALGO_DVB_CSA3 = 3,
    ALGO_AES_OFB = 4,
    ALGO_AES_SCTE = 5,
};

enum ca_sc2_algo_type {
    CA_ALGO_AES_ECB_CLR_END,
    CA_ALGO_AES_ECB_CLR_FRONT,
    CA_ALGO_AES_CBC_CLR_END,
    CA_ALGO_AES_CBC_IDSA,
    CA_ALGO_CSA2,
    CA_ALGO_DES_SCTE41,
    CA_ALGO_DES_SCTE52,
    CA_ALGO_TDES_ECB_CLR_END,
    CA_ALGO_CPCM_LSA_MDI_CBC,
    CA_ALGO_CPCM_LSA_MDD_CBC,
    CA_ALGO_CSA3,
    CA_ALGO_ASA,
    CA_ALGO_ASA_LIGHT
};

enum ca_sc2_dsc_type {
    CA_DSC_COMMON_TYPE,
    CA_DSC_TSD_TYPE,/*just support AES descramble.*/
    CA_DSC_TSE_TYPE/*just support AES enscramble.*/
};
#endif /*_SECMEM_TYPES_H_ */
