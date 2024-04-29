// Copyright (C) 2022 Amlogic, Inc. All rights reserved.
//
// All information contained herein is Amlogic confidential.
//
// This software is provided to you pursuant to Software License
// Agreement (SLA) with Amlogic Inc ("Amlogic"). This software may be
// used only in accordance with the terms of this agreement.
//
// Redistribution and use in source and binary forms, with or without
// modification is strictly prohibited without prior written permission
// from Amlogic.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef INCLUDE_WLCDMI_H_
#define INCLUDE_WLCDMI_H_

#include "wayland-client-core.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _WLCdmiSession        WLCdmiSession;
typedef struct _WLCdmiCrypto         WLCdmiCrypto;
typedef struct _WLCasContext      WLCasContext;


enum WLCDMI_SCHEME_TYPE
{
    WLCDMI_SCHEME_DEFAULT = 0,
    WLCDMI_SCHEME_CENC,
    WLCDMI_SCHEME_CENS,
    WLCDMI_SCHEME_CBC1,
    WLCDMI_SCHEME_CBCS,
};

enum WLCDMI_PARAM_INDEX
{
    WLCDMI_PARAM_UNUSED = 0,
    WLCDMI_PARAM_AUDIO_CODEC_TYPE,
    WLCDMI_PARAM_VMX_SERVER_ADDRESS,
};

enum WLCDMI_CUSTOM_EVENT_TYPE
{
    WLCDMI_CUSTOM_EVENT_UNUSED = 0,
    WLCDMI_CUSTOM_EVENT_KEY_RETRIEVAL_STATUS,
    WLCDMI_CUSTOM_EVENT_OUTPUT_CONTROL,
    WLCDMI_CUSTOM_EVENT_OPERATOR_DATA,
};

typedef struct {
    void (*key_message_callback)(WLCdmiSession *session,
            void* pUserData,
            const char *pbUrl,
            const uint8_t *pbChallenge,
            const uint32_t cbChallenge);
    void (*key_status_callback)(WLCdmiSession *session,
            void* pUserData,
            const char *pbStatus,
            const uint8_t *pbKeyId,
            const uint8_t cbKeyId);
    void (*key_ready_callback)(WLCdmiSession *session,
            void* pUserData);
    void (*key_error_callback)(WLCdmiSession *session,
            void* pUserData,
            uint32_t dwError,
            const char *pbMessage);
    void (*custom_event_callback)(WLCdmiSession *session,
            void* pUserData,
            uint32_t type,
            const char *pbEvent,
            const uint32_t cbEvent);
} wlcdmi_callback_t;

void wlcdmi_close();
WLCdmiSession *wlcdmi_open_session (const char *pbIdentifier,
        uint32_t dwType,
        uint32_t dwScheme,
        uint8_t *pbInitData,
        size_t cbInitData,
        uint8_t *pbCdmData,
        size_t cbCdmData,
        wlcdmi_callback_t *pCallback,
        void *pUserData);
void wlcdmi_session_close(WLCdmiSession *session);
int wlcdmi_session_run(WLCdmiSession *session);
int wlcdmi_session_update(WLCdmiSession *session,
        const uint8_t *pbResponse,
        uint32_t cbResponse);
void wlcdmi_session_set_parameter(WLCdmiSession *session,
        uint32_t paramIndex,
        uint8_t *pbParamData,
        size_t cbParamData);
WLCdmiCrypto *wlcdmi_session_open_crypto(WLCdmiSession *session,
        const uint8_t *pbKeyId,
        size_t cbKeyId,
        uint32_t flag);
void wlcdmi_crypto_close(WLCdmiCrypto *crypto);
int wlcdmi_crypto_decrypt_full(WLCdmiCrypto *crypto,
        uint32_t cIV,
        uint32_t cbIVData,
        uint8_t *pbIVData,
        uint32_t *pRegions,
        uint32_t cSubsample,
        uint32_t *pSubsample,
        uint32_t *pPattern,
        uint32_t cbEncrypted,
        uint8_t *pbEncrypted,
        int memFd);
int wlcdmi_crypto_decrypt_pattern(WLCdmiCrypto *crypto,
        uint32_t cbIVData,
        uint8_t *pbIVData,
        uint32_t cSubsample,
        uint32_t *pSubsample,
        uint32_t *pPattern,
        uint32_t cbEncrypted,
        uint8_t *pbEncrypted,
        int memFd);
int wlcdmi_crypto_decrypt_subsamples(WLCdmiCrypto *crypto,
        uint32_t cbIVData,
        uint8_t *pbIVData,
        uint32_t cSubsample,
        uint32_t *pSubsample,
        uint32_t cbEncrypted,
        uint8_t *pbEncrypted,
        int memFd);
int wlcdmi_crypto_decrypt(WLCdmiCrypto *crypto,
        uint32_t cbIVData,
        uint8_t *pbIVData,
        uint32_t cbEncrypted,
        uint8_t *pbEncrypted,
        int memFd);
const char *wlcdmi_version();
//////CAS/////////////////////////////////////////////////////////////////////////
enum WLCAS_EVENT_TYPE
{
    WLCAS_EVENT_PROVISION_STATUS = 0,      // 0: fail, 1: success
    WLCAS_EVENT_DESCRAMBLE_STATUS,         // 0: success, other value: refer ca document
    WLCAS_EVENT_FINGER_PRINT,
    WLCAS_EVENT_SET_PARAMETER,
    WLCAS_EVENT_SESSION_SELECT_AUDIO,

};
enum WLCAS_INFO_TYPE
{
    WLCAS_INFO_CHIPID = 1,
    WLCAS_INFO_CA_VERSION,
};

enum WLCAS_INTENT_TYPE
{
    WLCAS_INTENT_LIVE = 0,
    WLCAS_INTENT_RECORD,
    WLCAS_INTENT_PLAYBACK,
    WLCAS_INTENT_OTT,
    WLCAS_INTENT_INVALID,
};

typedef struct
{
    void (*cas_callback)(WLCasContext *context,
            void *pUserData,
            int event,
            int arg,
            const uint8_t *data,
            uint32_t size);
    void (*cas_session_callback)(WLCasContext *context,
            void *pUserData,
            int event,
            int arg,
            const uint8_t *data,
            uint32_t size,
            uint32_t sessionId);
} wlcas_callback_t;


WLCasContext *wlcas_open(const char *pbIdentifier,
            wlcas_callback_t *pCallback,
            void *pUserData); // support cas name and ca_system_id
int wlcas_set_private_data(WLCasContext *context,
            const uint8_t *pbPrivateData,
            uint32_t uSize);
int wlcas_provision(WLCasContext *context,
            const char *pbProvisionString,
            int timeout_ms);
int wlcas_process_emm(WLCasContext *context,
            const uint8_t *pbBuffer,
            uint32_t uSize);
int wlcas_send_event(WLCasContext *context,
            int event,
            int arg,
            const uint8_t *pbEventData,
            uint32_t uSize);
int wlcas_refresh_entitlements(WLCasContext *context,
            int refreshType,
            const uint8_t *pbRefreshData,
            uint32_t uSize);
int wlcas_get_info(WLCasContext *context,
            int iInfoType,
            uint8_t *pbBuffer,
            uint32_t *puSize);
void wlcas_close(WLCasContext *context);


uint32_t wlcas_context_open_session(WLCasContext *context,
            int intent,
            int mode);
int wlcas_session_set_private_data(WLCasContext *context,
            uint32_t sessionid,
            const uint8_t *pbPrivateData,
            uint32_t uSize);
int wlcas_session_process_ecm(WLCasContext *context,
            uint32_t sessionid,
            int isSection,
            int isvecm,
            int ecmpid,
            const uint8_t *pbBuffer,
            uint32_t uSize);
int wlcas_session_send_event(WLCasContext *context,
            uint32_t sessionid,
            int event,
            int arg,
            const uint8_t *pbEventData,
            uint32_t uSize);
int wlcas_session_decrypt(WLCasContext *context,
            uint32_t sessionid,
            uint8_t *pbBuffer,
            uint32_t uSize,
            int *piBytesProcessed);
void wlcas_session_close(WLCasContext *context,
            uint32_t sessionid);



#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_WLCDMI_H_ */
