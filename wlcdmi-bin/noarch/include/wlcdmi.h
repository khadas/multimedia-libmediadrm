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

typedef struct _WLCdmiSession        WLCdmiSession;
typedef struct _WLCdmiCrypto         WLCdmiCrypto;

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
} wlcdmi_callback_t;

void wlcdmi_close();
WLCdmiSession *wlcdmi_open_session (const char *pbIdentifier,
        uint32_t dwType,
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
#endif /* INCLUDE_WLCDMI_H_ */
