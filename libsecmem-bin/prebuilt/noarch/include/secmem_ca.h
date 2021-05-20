/*
 * secmem_ca.h
 *
 * Copyright (C) 2019 Amlogic, Inc. All rights reserved.
 *
 *  Created on: Feb 2, 2020
 *      Author: tao
 */


#ifndef _SECMEM_CA_H_
#define _SECMEM_CA_H_

#include <stdint.h>
#include <secmem_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FLAG_(x, mask, shift) ((x & (mask)) << shift)
#define SECMME_V2_FLAGS_TVP(x) FLAG_(x, 0xF, 0)
#define SECMME_V2_FLAGS_VP9(x) FLAG_(x, 0xF, 4)
#define SECMME_V2_FLAGS_VD_INDEX(x) FLAG_(x, 0xF, 9)
#define SECMME_V2_FLAGS_USAGE(x) FLAG_(x, 0x7, 13)

#define TSN_PATH             "/sys/class/stb/tsn_source"
#define TSN_IPTV             "local"
#define TSN_DVB              "demod"

/**
 * Common API
 */
unsigned int Secure_GetSecmemSize(void);
unsigned int Secure_GetVersion(void);
unsigned int Secure_NegotiateVersion(unsigned int expected);
unsigned int Secure_GetBufferConfig(uint32_t *count, uint32_t *size);

/**
 * V1 API
 */
unsigned int Secure_AllocSecureMem(unsigned int length,
                            unsigned int tvp_set);
unsigned int Secure_ReleaseResource(void);
unsigned int Secure_GetCsdDataDrmInfo(unsigned int srccsdaddr,
                            unsigned int csd_len,
                            unsigned int* store_csd_phyaddr,
                            unsigned int* store_csd_size,
                            unsigned int overwrite);
unsigned int Secure_GetPadding(unsigned int* pad_addr,
                            unsigned int* pad_size,
                            unsigned int pad_type);
unsigned int Secure_GetVp9HeaderSize(void *src,
                            unsigned int size,
                            unsigned int *header_size);

/**
 * V2 API
 */
unsigned int Secure_V2_SessionCreate(void **sess);
unsigned int Secure_V2_SessionDestroy(void **sess);
unsigned int Secure_V2_Init(void *sess,
                           uint32_t source,
                           uint32_t flags,
                           uint32_t paddr,
                           uint32_t msize);
unsigned int Secure_V2_MemCreate(void *sess,
                           uint32_t *handle);
unsigned int Secure_V2_MemAlloc(void *sess,
                           uint32_t handle,
                           uint32_t size,
                           uint32_t *phyaddr);
unsigned int Secure_V2_MemToPhy(void *sess,
                           uint32_t handle,
                           uint32_t *phyaddr);
unsigned int Secure_V2_MemFill(void *sess,
                           uint32_t handle,
                           uint32_t offset,
                           uint8_t *buffer,
                           uint32_t size);
unsigned int Secure_V2_MemCheck(void *sess,
                           uint32_t handle,
                           uint8_t *buffer,
                           uint32_t len);
unsigned int Secure_V2_MemExport(void *sess,
                           uint32_t handle,
                           int *fd,
                           uint32_t *maxsize);
unsigned int Secure_V2_FdToHandle(void *sess,
                           int fd);
unsigned int Secure_V2_FdToPaddr(void *sess,
                           int fd);
unsigned int Secure_V2_MemFree(void *sess,
                           uint32_t handle);
unsigned int Secure_V2_MemRelease(void *sess,
                           uint32_t handle);
unsigned int Secure_V2_MemFlush(void *sess);
unsigned int Secure_V2_MemClear(void *sess);
unsigned int Secure_V2_SetCsdData(void*sess,
                           unsigned char *csd,
                           unsigned int csd_len);
unsigned int Secure_V2_GetCsdDataDrmInfo(void *sess,
                           unsigned int srccsdaddr,
                           unsigned int csd_len,
                           unsigned int *store_csd_phyaddr,
                           unsigned int *store_csd_size,
                           unsigned int overwrite);
unsigned int Secure_V2_GetPadding(void *sess,
                           unsigned int* pad_addr,
                           unsigned int *pad_size,
                           unsigned int pad_type);
unsigned int Secure_V2_GetVp9HeaderSize(void *sess,
                           void *src,
                           unsigned int size,
                           unsigned int *header_size,
                           uint32_t *frames);
unsigned int Secure_V2_MergeCsdDataDrmInfo(void *sess,
                           uint32_t *phyaddr,
                           uint32_t *csdlen);
unsigned int Secure_V2_MergeCsdData(void *sess,
                           uint32_t handle,
                           uint32_t *csdlen);
unsigned int Secure_V2_Parse(void *sess,
                           uint32_t type,
                           uint32_t handle,
                           uint8_t *buffer,
                           uint32_t size,
                           uint32_t *flag);
unsigned int Secure_V2_ResourceAlloc(void *sess,
                           uint32_t* phyaddr,
                           uint32_t *size);
unsigned int Secure_V2_ResourceFree(void *sess);
unsigned int Secure_V2_BindTVP(void *sess,
                           uint32_t cas_id);
unsigned int Secure_V2_AudioValid(void *sess,
                           void *src, // secure source phyaddr
                           unsigned int size, //secure packet size
                           unsigned int aud_type, // audio format AUD_VALID_TYPE
                           unsigned char *aud_buf, // nonsecure output buf
                           unsigned int buf_max_size); // aud_buf total size
unsigned int Secure_V2_GetSecmemSize(void *sess,
                           unsigned int *mem_capacity,
                           unsigned int *mem_available,
                           unsigned int *handle_capacity,
                           unsigned int *handle_available);


/*
 * Sideband API
 */
unsigned int Secure_SetHandle(uint32_t handle);
unsigned int Secure_GetHandle(uint32_t *handle);

/*
 * Cas API
 */
int Secure_SetTSNSource(const char *tsn_path,
                           const char *tsn_from);

int Secure_CreateDscCtx(
                           void **secmem_sess);

int Secure_CreateDscPipeline(
                           void *secmem_sess,
                           int cas_dsc_idx,
                           uint32_t video_id,
                           uint32_t audio_id,
                           bool av_diff_ecm,
                           int cur_sid);

void Secure_GetDscParas(
                           cas_crypto_mode mode,
                           ca_sc2_algo_type *dsc_algo,
                           ca_sc2_dsc_type *dsc_type);

int Secure_StartDescrambling(
                           void *secmem_sess,
                           int dsc_algo,
                           int dsc_type,
                           int video_cas_sid,
                           int audio_cas_sid);

int Secure_StopDescrambling(
                           void *secmem_sess);

int Secure_DestroyDscCtx(
                           void **secmem_sess);

#ifdef __cplusplus
}
#endif


#endif /* _SECMEM_CA_H_ */
