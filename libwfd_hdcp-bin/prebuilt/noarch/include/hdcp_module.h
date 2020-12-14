/*
 * Copyright (c) 2020, Amlogic.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __AML_WFD_HDCP_MODULE_H__
#define __AML_WFD_HDCP_MODULE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>

/** Define Function's return value */
typedef enum {
     HDCP_RESULT_SUCCESS = 0,
     HDCP_RESULT_ERROR_INVALID_PARAMETER,
     HDCP_RESULT_ERROR_INVALID_ADDRESS,
     HDCP_RESULT_ERROR_OUT_OF_MEM,
     HDCP_RESULT_ERROR_SPEC_VERSION,
     HDCP_RESULT_ERROR_KEY_ERR,
     HDCP_RESULT_ERROR_AUTH_ERR,
     HDCP_RESULT_ERROR_DISCONNECTED,
     HDCP_RESULT_ERROR_TEE_ERR,
     HDCP_RESULT_ERROR_DECRYPT_ERR,
     HDCP_RESULT_ERROR_INTERNAL,
     HDCP_RESULT_MAX_VALUE,
} amlWfdHdcpResultType;

/** Define support HDCP level */
typedef enum {
    HDCP_LEVEL_NONE = 0,        //No hdcp
    HDCP_LEVEL_14,              //For hdcp 1.4
    HDCP_LEVEL_20,              //For hdcp 2.0
    HDCP_LEVEL_21,              //For hdcp 2.1
    HDCP_LEVEL_22,              //For hdcp 2.2
    HDCP_LEVEL_23,              //For hdcp 2.3
} amlWfdHdcpLevel;

/** Define the callback event for async notify the init deinit and connect event */
typedef enum
{
    HDCP_EVENT_INITIALIZATION_COMPLETE = 0,       //Async notify init success
    HDCP_EVENT_INITIALIZATION_FAILED,             //Async notify init failed
    HDCP_EVENT_SHUTDOWN_COMPLETE,                 //Async notify shutdown success
    HDCP_EVENT_SPEC_VERSION_NOT_SUPPORT,          //Async notify not support' tx version
    HDCP_EVENT_AUTH_DISCONNECTED,                 //Async notify rx tx auth process disconnected
    HDCP_EVENT_AUTH_ERROR,                        //Async notify auth error
    HDCP_EVENT_INTERNAL_ERROR,                    //Async notify nternal error
    HDCP_EVENT_MAX_VALUE
} amlWfdHdcpEventType;

typedef void *  amlWfdHdcpHandle;

/** Define encrypt and decrypt's information */
typedef struct amlWfdHdcpDataInfo
{
    uint32_t isAudio;               //[IN]    audio use clear buffer should be set to 0 and video is use secure buffer set to 1
    uint8_t * in;                   //[INOUT] a buffer pointer for input encrypt buffer
    uint8_t * out;                  //[INOUT] a buffer pointer for output decrypt buffer for audio in and out can be same
    uint32_t inSize;                //[IN]    input buffer's data's size, must be sure out's buffer size is >= (inputbuffer's size + 4)
    uint32_t outSize;               //[INOUT] the decrypt data's size
    uint32_t streamCtr;             //[IN]    which from pes data
    uint64_t inputCtr;              //[IN]    which from pes data
    uint64_t pts;                   //[IN]    for next step support output es data not pes reserved
    void * privateData;             //[INOUT] for next step support output es data not pes reserved
} * amlWfdHdcpDataInfoPtr;

/** Define event receiver callbacktype */

typedef void (*amlWfdHdcpEventCallback)(amlWfdHdcpHandle handle, amlWfdHdcpEventType event);

/**
    Define module init function, this functiom must be this first calling to get a handle
    Paras:
        host:     [IN]     source's address     can be null, then use 127.0.0.1 as default address
        port:     [IN]     hdcp connect's port  can't be 0, must be a valid value 0 ~ 65535
        callback: [IN]     event callback       can't be null, must a valid callback function pointer
        handle:   [IN/OUT] module handle        can't be null
    Retrun:
        Success return HDCP_RESULT_SUCCESS
        Failed  return other
*/
amlWfdHdcpResultType amlWfdHdcpInitAsync(const char * host, uint16_t port, amlWfdHdcpEventCallback callback,
                             amlWfdHdcpHandle * handle);

/**
    Define deinit interface to release the alloc source
    Para:
        handle:   [IN] which return from amlWfdHdcpInitAsync
    Return:
        success return HDCP_RESULT_SUCCESS
        failed return other
*/
amlWfdHdcpResultType amlWfdHdcpDeinitAsync(amlWfdHdcpHandle handle);

/**
    Define deinit interface to release the handle
    Para:
        handle:   [IN] which return from amlWfdHdcpInitAsync
    Return:
        success return HDCP_RESULT_SUCCESS
        failed return other
*/
amlWfdHdcpResultType amlWfdDestroyHandle(amlWfdHdcpHandle handle);

/**
    Define module init function.
    Paras:
        host:   [IN]        source's address     can be null, then use 127.0.0.1 as default address
        port:   [IN]        hdcp connect's port  can't be 0, must be a valid value 0 ~ 65535
        handle: [IN/OUT]    amlWfdHdcpHandle * type handle, success is not null or failed will be null
    Retrun:
        Success return HDCP_RESULT_SUCCESS
        Failed  return other
*/
amlWfdHdcpResultType amlWfdHdcpInit(const char * host, uint16_t port, amlWfdHdcpHandle * handle);

/**
    Define deinit interface to release the alloc source
    Para:
        handle:     [IN] which return from amlWfdHdcpInitAsync
    Return:
        success return HDCP_RESULT_SUCCESS
        failed return  other
*/
amlWfdHdcpResultType amlWfdHdcpDeinit(amlWfdHdcpHandle handle);

/**
    Define decrypt interface
    Paras:
        handle:     [IN]     which return from amlWfdHdcpInitAsync
        data:       [IN/OUT] a pointer type which indicate decrypt data information for example in/out and so on
    Return:
        Success HDCP_RESULT_SUCCESS
        Failed  return other
*/
amlWfdHdcpResultType amlWfdHdcpDecrypt(amlWfdHdcpHandle handle, amlWfdHdcpDataInfoPtr data);

/**
    Define interface to return support HDCP level
    Paras:
        handle:     [IN]    which return from amlWfdHdcpInitAsync
        levle :     [INOUT] used to received the support hdcp level
    Return:
    Return:
        Success HDCP_RESULT_SUCCESS
        Failed  return other
*/
amlWfdHdcpResultType amlWfdHdcpGetSupportLevel(amlWfdHdcpHandle handle, amlWfdHdcpEventType * level);

#ifdef __cplusplus
}
#endif
#endif