// Copyright 2018 Google LLC. All Rights Reserved. This file and proprietary
// source code may only be used and distributed under the Widevine Master
// License Agreement.

/**
 * @mainpage OEMCrypto API
 *
 * OEMCrypto is the low level library implemented by the OEM to provide key and
 * content protection, usually in a separate secure memory or process space. The
 * term *OEMCrypto* refers to both the API described here and the library
 * implementing the API.
 *
 * For an overview of OEMCrypto functionality, please see
 * [Widevine Modular DRM Security Integration Guide for Common
 * Encryption](../oemcrypto)
 *
 * The OEMCrypto API is divided into several sections.
 *
 * @defgroup initcontrol Initialization and Control API
 *  Initialization and set up OEMCrypto.
 *
 * @defgroup keyladder Crypto Key Ladder API
 * The crypto key ladder is a mechanism for staging crypto keys for use by the
 * hardware crypto engine.
 *
 * Keys are always encrypted for transmission.  Before
 * a key can be used, it must be decrypted (typically using the top key in the
 * key ladder) and then added to the key ladder for upcoming decryption
 * operations.  The Crypto Key Ladder API requires the device to provide
 * hardware support for AES-128 CTR and CBC modes and prevent clear keys from
 * being exposed to the insecure OS.
 *
 * @defgroup decryption Decryption API
 * Devices that implement the Key Ladder API must also support a secure decode
 * or secure decode and rendering implementation.
 *
 * This can be done by either
 * decrypting into buffers secured by hardware protections and providing these
 * secured buffers to the decoder/renderer or by implementing decrypt operations
 * in the decoder/renderer.
 *
 * In a Security Level 2 implementation where the video path is not protected,
 * the audio and video streams are decrypted using OEMCrypto_DecryptCENC() and
 * buffers are returned to the media player in the clear.
 *
 * Generic Modular DRM allows an application to encrypt, decrypt, sign and
 * verify arbitrary user data using a content key.  This content key is
 * securely delivered from the server to the client device using the same
 * factory installed root of trust as a media content keys.
 *
 * @defgroup factory_provision Factory Provisioning API
 * Functions that are used to install the root of trust. This could be either a
 * keybox or an OEM Certificate.
 *
 * Widevine keyboxes are used to establish a root of trust to secure content on
 * a device that uses Provisioning 2.0.  OEM Certificates are used to establish
 * a root of trust to secure content on a device that uses Provisioning
 * 3.0. Factory Provisioning a device is related to manufacturing methods. This
 * section describes the API that installs the Widevine Keybox and the
 * recommended methods for the OEM’s factory provisioning procedure.
 *
 * Starting with API version 10, devices should have two keyboxes.  One is the
 * production keybox which may be installed in the factory, or using
 * OEMCrypto_WrapKeyboxOrOEMCert and OEMCrypto_InstallKeyboxOrOEMCert as
 * described below.  The second keybox is a test keybox.  The test keybox is the
 * same for all devices and is used for a suite of unit tests.  The test keybox
 * will only be used temporarily while the unit tests are running, and will not
 * be used by the general public.  After the unit tests have been run, and
 * OEMCrypto_Terminate has been called, the production keybox should be active
 * again.
 *
 * API functions marked as optional may be used by the OEM’s factory
 * provisioning procedure and implemented in the library, but are not called
 * from the Widevine DRM Plugin during normal operation.
 *
 * @defgroup keybox Keybox and Provisioning 2.0 API
 * Functions that are needed to for a device with a keybox.
 *
 * The OEMCrypto API allows for a device to be initially provisioned with a
 * keybox or with an OEM certificate.  See the section Provisioning above.  In a
 * Level 1 or Level 2 implementation, only the security processor may access the
 * keys in the keybox.  The following functions are for devices that are
 * provisioned with a keybox, i.e. Provisioning 2.0.
 *
 * @defgroup oem_cert OEM Certificate and Provisioning 3.0 API
 * Functions that are needed to for a device with an OEM Certificate.
 *
 * The OEMCrypto API allows for a device to be initially provisioned with a
 * keybox or with an OEM certificate.  See the Provisioning above.  The
 * functions in this section are for devices that are provisioned with an OEM
 * Certificate, i.e. Provisioning 3.0.
 *
 * API functions marked as optional may be used by the OEM’s factory
 * provisioning procedure and implemented in the library, but are not called
 * from the Widevine DRM Plugin during normal operation.
 *
 * @defgroup validation Validation and Feature Support API
 * The OEMCrypto API is flexible enough to allow different devices to support
 * different features.  This section has functions that specify the level of
 * support for various features.  These values are reported to either the
 * application or the license server.
 *
 * @defgroup drm_cert DRM Certificate Provisioning API
 * This section of functions are used to provision the device with an DRM
 * certificate.  This certificate is obtained by a device in the field from a
 * Google/Widevine provisioning server, or from a third party server running the
 * Google/Widevine provisioning server SDK.  Since the DRM certificate may be
 * origin or application specific, a device may have several DRM certificates
 * installed at a time.  The DRM certificate is used to authenticate the device
 * to a license server.  In order to obtain a DRM certificate from a
 * provisioning server, the device may authenticate itself using a keybox or
 * using an OEM certificate.
 *
 * @defgroup usage_table Usage Table API
 * The usage table is used to store license usage and allows a persistent
 * license to be reloaded.
 *
 * @defgroup test_verify Test and Verification API
 * Functions that are designed to help test OEMCrypto and the device. They are
 * not used during normal operation.  Some functions, like OEMCrypto_RemoveSRM
 * should only be implemented on test devices.  Other functions, like those that
 * test the full decrypt data path may be supported on a production device with
 * no added risk of security loss.
 *
 * The following functions are used just for testing and verification of
 * OEMCrypto and the CDM code.
 *
 * @defgroup common_types Common Types
 * Enumerations and structures that are used by several OEMCrypto and ODK
 * functions.
 */

#ifndef OEMCRYPTO_CENC_H_
#define OEMCRYPTO_CENC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "OEMCryptoCENCCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

/// @addtogroup keyladder
/// @{

/// This is the internal session identifier.
typedef uint32_t OEMCrypto_SESSION;

/// @}

/// @addtogroup decryption
/// @{
/**
 * The memory referenced by OEMCrypto_SharedMemory* is safe to be placed in
 * shared memory. The only data that should be placed into shared
 * memory is the contents of input/output buffers, i.e. data that will
 * not introduce security vulnerabilities if it is subject to
 * modification while being accessed.
 */
typedef uint8_t OEMCrypto_SharedMemory;

/** Specifies destination buffer type.
 */
typedef enum OEMCryptoBufferType {
  OEMCrypto_BufferType_Clear,
  OEMCrypto_BufferType_Secure,
  OEMCrypto_BufferType_Direct,
  OEMCrypto_BufferType_MaxValue = OEMCrypto_BufferType_Direct,
} OEMCryptoBufferType;

/**
 * This structure is used as parameters in the OEMCrypto_DecryptCENC and
 * OEMCrypto_CopyBuffer functions. This describes the type and access
 * information for the memory to receive decrypted data.
 *
 * The OEMCrypto API supports a range of client device architectures.  Different
 * architectures have different methods for acquiring and securing buffers that
 * will hold portions of the audio or video stream after decryption. Three basic
 * strategies are recognized for handling decrypted stream data:
 *
 * 1. Return the decrypted data in the clear into normal user memory
 *    (ClearBuffer). The caller uses normal memory allocation methods to
 *    acquire a buffer, and supplies the memory address of the buffer in
 *    the descriptor.
 * 2. Place the decrypted data into protected memory (SecureBuffer). The
 *    caller uses a platform-specific method to acquire the protected
 *    buffer and a user-memory handle that references it. The handle is
 *    supplied to the decrypt call in the descriptor.  If the buffer is
 *    filled with several OEMCrypto calls, the same handle will be used,
 *    and the offset will be incremented to indicate where the next write
 *    should take place.
 * 3. Place the decrypted data directly into the audio or video decoder
 *    fifo (Direct). The caller will use platform-specific methods to
 *    initialize the fifo and the decoders. The decrypted stream data is
 *    not accessible to the caller. This is used on some platforms only.
 *
 * @param[in] type: A tag that indicates which variant of the union is valid for
 *    this instance of the structure. [variant] clear: This variant is valid
 *    when the type is OEMCrypto_BufferType_Clear. This OEMCrypto_DestBufferDesc
 *    indicates output should be written to a clear buffer.
 * @param[in] address: A pointer to the address in memory to begin writing
 *    output.
 * @param[in] address_length: The length of the buffer that is available to
 *    contain output. [variant] secure: This variant is valid when the type is
 *    OEMCrypto_BufferType_Secure. This OEMCrypto_DestBufferDesc indicates
 *    output should be written to a secure buffer. The decrypted output must
 *    never leave the secure area until it is output from the device.
 * @param[in] handle: An opaque handle to a secure buffer. The meaning of this
 *    handle is platform-specific.
 * @param[in] handle_length: The length of the data contained in the secure
 *    buffer.
 * @param[in] offset: An offset indicating where in the secure buffer to start
 *    writing data.  [variant] direct: This variant is valid when the type is
 *    OEMCrypto_BufferType_Direct. This OEMCrypto_DestBufferDesc indicates
 *    output should be written directly to the decoder.
 * @param[in] is_video: A flag indicating if the data is video and should be
 *    sent to the video decoder. If this is false, the data can be assumed to be
 *    audio and sent to the audio decoder.
 *
 * @version
 *   This struct changed in API version 16.
 */
typedef struct {
  OEMCryptoBufferType type;
  union {
    struct {  // type == OEMCrypto_BufferType_Clear
      OEMCrypto_SharedMemory* address;
      size_t address_length;
    } clear;
    struct {  // type == OEMCrypto_BufferType_Secure
      void* handle;
      size_t handle_length;
      size_t offset;
    } secure;
    struct {  // type == OEMCrypto_BufferType_Direct
      bool is_video;
    } direct;
  } buffer;
} OEMCrypto_DestBufferDesc;

/**
 * This structure is used as parameters in the OEMCrypto_DecryptCENC function.
 *
 * @param[in] input_data: An unaligned pointer to this sample from the stream.
 * @param[in] input_data_length: The length of this sample in the stream, in
 *    bytes.
 * @param[in] output_descriptor: A caller-owned descriptor that specifies the
 *    handling of the decrypted byte stream. See OEMCrypto_DestbufferDesc for
 *    details.
 *
 * @version
 *   This struct changed in API version 16.
 */
typedef struct {
  const OEMCrypto_SharedMemory* input_data;    // source for encrypted data.
  size_t input_data_length;                    // length of encrypted data.
  OEMCrypto_DestBufferDesc output_descriptor;  // destination for clear data.
} OEMCrypto_InputOutputPair;

/**
 * This structure is used as parameters in the OEMCrypto_DecryptCENC
 * function. In the DASH specification, a sample is composed of multiple
 * samples, and each subsample is composed of two regions. The first region is
 * clear unprotected data. We also call this clear data or unencrypted
 * data. Immediately following the clear region is the protected region. The
 * protected region is encrypted or encrypted with a pattern. The pattern and
 * number of bytes that are encrypted in the protected region is discussed in
 * this document when we talk about the function OEMCryptoDecryptCENC. For
 * historic reasons, this document also calls the protected region the encrypted
 * region.
 *
 * @param[in] num_bytes_clear: The number of unprotected bytes in this
 *    subsample. The clear bytes come before the encrypted bytes.
 * @param[in] num_bytes_encrypted: The number of protected bytes in this
 *    subsample. The protected bytes come after the clear bytes.
 * @param[in] subsample_flags: bitwise flags indicating if this is the first,
 *    middle, or last subsample in a sample. 1 = first subsample, 2 = last
 *    subsample, 3 = both first and last subsample, 0 = neither first nor last
 *    subsample.
 * @param[in] block_offset: This will only be non-zero for the 'cenc' scheme.
 *    If it is non-zero, the decryption block boundary is different from the
 *    start of the data. block_offset should be subtracted from data to compute
 *    the starting address of the first decrypted block. The bytes between the
 *    decryption block start address and data are discarded after decryption. It
 *    does not adjust the beginning of the source or destination data. This
 *    parameter satisfies 0 <= block_offset < 16.
 *
 * @version
 *   This struct changed in API version 16.
 */
typedef struct {
  size_t num_bytes_clear;
  size_t num_bytes_encrypted;
  uint8_t subsample_flags;  // is this the first/last subsample in a sample?
  size_t block_offset;      // used for CTR "cenc" mode only.
} OEMCrypto_SubSampleDescription;

#define OEMCrypto_FirstSubsample 1
#define OEMCrypto_LastSubsample 2

/**
 * This structure is used as parameters in the OEMCrypto_DecryptCENC function.
 *
 * @param[in] buffers: A structure containing information about the input and
 *    output buffers.
 * @param[in] iv: A 16-byte array containing the IV for the initial subsample of
 *    the sample.
 * @param[in] subsamples: A caller-owned array of OEMCrypto_SubSampleDescription
 *    structures. Each entry in this array describes one subsample in the
 *    sample.
 * @param[in] subsamples_length: The length of the array pointed to by the
 *    subsamples parameter.
 *
 * @version
 *   This struct changed in API version 16.
 */
typedef struct {
  OEMCrypto_InputOutputPair buffers;  // The source and destination buffers.
  uint8_t iv[16];                     // The IV for the initial subsample.
  const OEMCrypto_SubSampleDescription* subsamples;  // subsamples array.
  size_t subsamples_length;  // the number of subsamples in the sample.
} OEMCrypto_SampleDescription;

/**
 * This structure is used as parameters in the OEMCrypto_DecryptCENC function.
 *
 * Fields:
 * @param[in] encrypt: The number of 16-byte crypto blocks to encrypt.
 * @param[in] skip: The number of 16-byte crypto blocks to leave in the clear.
 *
 * @version
 *   This struct changed in API version 16.
 */
typedef struct {
  size_t encrypt;  // number of 16 byte blocks to decrypt.
  size_t skip;     // number of 16 byte blocks to leave in clear.
} OEMCrypto_CENCEncryptPatternDesc;

/**
 * OEMCryptoCipherMode is used in SelectKey to prepare a key for either CTR
 * decryption or CBC decryption.
 */
typedef enum OEMCryptoCipherMode {
  OEMCrypto_CipherMode_CTR,
  OEMCrypto_CipherMode_CBC,
  OEMCrypto_CipherMode_MaxValue = OEMCrypto_CipherMode_CBC,
} OEMCryptoCipherMode;

/**
 * Contains encrypted content key data for loading into the sessions keytable.
 * The content key data is encrypted using AES-256-CBC encryption, with PKCS#7
 * padding.

 * @param entitlement_key_id: entitlement key id to be matched to key table.
 * @param entitlement_key_id_length: length of entitlment_key_id in bytes (1 to
 *     16).
 * @param content_key_id: content key id to be loaded into key table.
 * @param content_key_id_length: length of content key id in bytes (1 to 16).
 * @param key_data_iv: the IV for performing AES-256-CBC decryption of the key
 *    data.
 * @param key_data: encrypted content key data.
 * @param key_data_length: length of key_data: 16 or 32 depending on intended us
 e.
 */
typedef struct {
  OEMCrypto_Substring entitlement_key_id;
  OEMCrypto_Substring content_key_id;
  OEMCrypto_Substring content_key_data_iv;
  OEMCrypto_Substring content_key_data;
} OEMCrypto_EntitledContentKeyObject;

/**
 * This is a list of valid algorithms for OEMCrypto_Generic_* functions.
 * Some are valid for encryption/decryption, and some for signing/verifying.
 */
typedef enum OEMCrypto_Algorithm {
  OEMCrypto_AES_CBC_128_NO_PADDING = 0,
  OEMCrypto_HMAC_SHA256 = 1,
} OEMCrypto_Algorithm;

/// @}

/// @addtogroup keyladder
/// @{
/**
 * This structure is being deprecated. It is only used for legacy licenses.
 * Points to the relevant fields for renewing a content key. The fields are
 * extracted from the License Renewal Response message offered to
 * OEMCrypto_RefreshKeys(). Each field points to one of the components of
 * the key.

 * @param key_id: the unique id of this key.
 * @param key_control_iv: the IV for performing AES-128-CBC decryption of the
 *    key_control field. 16 bytes.
 * @param key_control: the key control block. It is encrypted (AES-128-CBC) with
 *    the content key from the key_data field. 16 bytes.
 *
 *  The key_data is unchanged from the original OEMCrypto_LoadKeys() call. Some
 *  Key Control Block fields, especially those related to key lifetime, may
 *  change.
 *
 *  The memory for the OEMCrypto_KeyRefreshObject fields is allocated and freed
 *  by the caller of OEMCrypto_RefreshKeys().
 */
typedef struct {
  OEMCrypto_Substring key_id;
  OEMCrypto_Substring key_control_iv;
  OEMCrypto_Substring key_control;
} OEMCrypto_KeyRefreshObject;

/// @}

/// @addtogroup usage_table
/// @{

#if 0  // If your compiler supports __attribute__((packed)).
/**
 * OEMCrypto_PST_Report is used to report an entry from the Usage Table.
 *
 * Platforms that have compilers that support packed structures, may use the
 * following definition.  Other platforms may use the header pst_report.h which
 * defines a wrapper class.
 *
 * All fields are in network byte order.
 */
typedef struct {
  uint8_t signature[20];  //  -- HMAC SHA1 of the rest of the report.
  uint8_t status;  // current status of entry. (OEMCrypto_Usage_Entry_Status)
  uint8_t clock_security_level;
  uint8_t pst_length;
  uint8_t padding;                         // make int64's word aligned.
  int64_t seconds_since_license_received;  // now - time_of_license_received
  int64_t seconds_since_first_decrypt;     // now - time_of_first_decrypt
  int64_t seconds_since_last_decrypt;      // now - time_of_last_decrypt
  uint8_t pst[];
} __attribute__((packed)) OEMCrypto_PST_Report;
#endif

/**
 * Valid values for clock_security_level in OEMCrypto_PST_Report.
 */
typedef enum OEMCrypto_Clock_Security_Level {
  kInsecureClock = 0,
  kSecureTimer = 1,
  kSecureClock = 2,
  kHardwareSecureClock = 3
} OEMCrypto_Clock_Security_Level;

typedef uint8_t RSA_Padding_Scheme;
// RSASSA-PSS with SHA1.
#define kSign_RSASSA_PSS ((RSA_Padding_Scheme)0x1)
// PKCS1 with block type 1 padding (only).
#define kSign_PKCS1_Block1 ((RSA_Padding_Scheme)0x2)

/// @}

/// @addtogroup validation
/// @{
/**
 * OEMCrypto_HDCP_Capability is used in the key control block to enforce HDCP
 * level, and in GetHDCPCapability for reporting.
 */
typedef enum OEMCrypto_HDCP_Capability {
  HDCP_NONE = 0,                 // No HDCP supported, no secure data path.
  HDCP_V1 = 1,                   // HDCP version 1.x
  HDCP_V2 = 2,                   // HDCP version 2.0 Type 1.
  HDCP_V2_1 = 3,                 // HDCP version 2.1 Type 1.
  HDCP_V2_2 = 4,                 // HDCP version 2.2 Type 1.
  HDCP_V2_3 = 5,                 // HDCP version 2.3 Type 1.
  HDCP_NO_DIGITAL_OUTPUT = 0xff  // No digital output.
} OEMCrypto_HDCP_Capability;

/**
   Return value for OEMCrypto_GetProvisioningMethod().
 */
typedef enum OEMCrypto_ProvisioningMethod {
  OEMCrypto_ProvisioningError = 0,  // Device cannot be provisioned.
  OEMCrypto_DrmCertificate = 1,     // Device has baked in DRM certificate
                                    // (level 3 only)
  OEMCrypto_Keybox = 2,        // Device has factory installed unique keybox.
  OEMCrypto_OEMCertificate = 3 // Device has factory installed OEM certificate.
} OEMCrypto_ProvisioningMethod;

/**
 * Flags indicating public/private key types supported.
 */
#define OEMCrypto_Supports_RSA_2048bit 0x1
#define OEMCrypto_Supports_RSA_3072bit 0x2
#define OEMCrypto_Supports_RSA_CAST   0x10
#define OEMCrypto_Supports_ECC_secp256r1 0x100
#define OEMCrypto_Supports_ECC_secp384r1 0x200
#define OEMCrypto_Supports_ECC_secp521r1 0x400

/**
 * Flags indicating full decrypt path hash supported.
 */
#define OEMCrypto_Hash_Not_Supported 0
#define OEMCrypto_CRC_Clear_Buffer 1
#define OEMCrypto_Partner_Defined_Hash 2

/**
 * Return values from OEMCrypto_GetAnalogOutputFlags.
 */
#define OEMCrypto_No_Analog_Output            0x0
#define OEMCrypto_Supports_Analog_Output      0x1
#define OEMCrypto_Can_Disable_Analog_Ouptput  0x2
#define OEMCrypto_Supports_CGMS_A             0x4
// Unknown_Analog_Output is used only for backwards compatibility.
#define OEMCrypto_Unknown_Analog_Output       (1<<31)

/// @}

/**
 * Obfuscation Renames.
 */
// clang-format off
#define OEMCrypto_Initialize                  _oecc01
#define OEMCrypto_Terminate                   _oecc02
#define OEMCrypto_InstallKeybox               _oecc03
// Rename InstallKeybox to InstallKeyboxOrOEMCert.
#define OEMCrypto_InstallRootKeyCertificate   _oecc03
#define OEMCrypto_InstallKeyboxOrOEMCert      _oecc03
#define OEMCrypto_GetKeyData                  _oecc04
#define OEMCrypto_IsKeyboxValid               _oecc05
// Rename IsKeyboxValid to IsKeyboxOrOEMCertValid.
#define OEMCrypto_IsRootKeyCertificateValid   _oecc05
#define OEMCrypto_IsKeyboxOrOEMCertValid      _oecc05
#define OEMCrypto_GetRandom                   _oecc06
#define OEMCrypto_GetDeviceID                 _oecc07
#define OEMCrypto_WrapKeybox                  _oecc08
// Rename WrapKeybox to WrapKeyboxOrOEMCert
#define OEMCrypto_WrapRootKeyCertificate      _oecc08
#define OEMCrypto_WrapKeyboxOrOEMCert         _oecc08
#define OEMCrypto_OpenSession                 _oecc09
#define OEMCrypto_CloseSession                _oecc10
#define OEMCrypto_DecryptCTR_V10              _oecc11
#define OEMCrypto_GenerateDerivedKeys_V15     _oecc12
#define OEMCrypto_GenerateSignature           _oecc13
#define OEMCrypto_GenerateNonce               _oecc14
#define OEMCrypto_LoadKeys_V8                 _oecc15
#define OEMCrypto_RefreshKeys_V14             _oecc16
#define OEMCrypto_SelectKey_V13               _oecc17
#define OEMCrypto_RewrapDeviceRSAKey          _oecc18
#define OEMCrypto_LoadDeviceRSAKey            _oecc19
#define OEMCrypto_GenerateRSASignature_V8     _oecc20
#define OEMCrypto_DeriveKeysFromSessionKey    _oecc21
#define OEMCrypto_APIVersion                  _oecc22
#define OEMCrypto_SecurityLevel               _oecc23
#define OEMCrypto_Generic_Encrypt             _oecc24
#define OEMCrypto_Generic_Decrypt             _oecc25
#define OEMCrypto_Generic_Sign                _oecc26
#define OEMCrypto_Generic_Verify              _oecc27
#define OEMCrypto_GetHDCPCapability_V9        _oecc28
#define OEMCrypto_SupportsUsageTable          _oecc29
#define OEMCrypto_UpdateUsageTable            _oecc30
#define OEMCrypto_DeactivateUsageEntry_V12    _oecc31
#define OEMCrypto_ReportUsage                 _oecc32
#define OEMCrypto_DeleteUsageEntry            _oecc33
#define OEMCrypto_DeleteOldUsageTable         _oecc34
#define OEMCrypto_LoadKeys_V9_or_V10          _oecc35
#define OEMCrypto_GenerateRSASignature        _oecc36
#define OEMCrypto_GetMaxNumberOfSessions      _oecc37
#define OEMCrypto_GetNumberOfOpenSessions     _oecc38
#define OEMCrypto_IsAntiRollbackHwPresent     _oecc39
#define OEMCrypto_CopyBuffer_V14              _oecc40
#define OEMCrypto_QueryKeyControl             _oecc41
#define OEMCrypto_LoadTestKeybox_V13          _oecc42
#define OEMCrypto_ForceDeleteUsageEntry       _oecc43
#define OEMCrypto_GetHDCPCapability           _oecc44
#define OEMCrypto_LoadTestRSAKey              _oecc45
#define OEMCrypto_Security_Patch_Level        _oecc46
#define OEMCrypto_LoadKeys_V11_or_V12         _oecc47
#define OEMCrypto_DecryptCENC_V15             _oecc48
#define OEMCrypto_GetProvisioningMethod       _oecc49
#define OEMCrypto_GetOEMPublicCertificate_V15 _oecc50
#define OEMCrypto_RewrapDeviceRSAKey30        _oecc51
#define OEMCrypto_SupportedCertificates       _oecc52
#define OEMCrypto_IsSRMUpdateSupported        _oecc53
#define OEMCrypto_GetCurrentSRMVersion        _oecc54
#define OEMCrypto_LoadSRM                     _oecc55
#define OEMCrypto_LoadKeys_V13                _oecc56
#define OEMCrypto_RemoveSRM                   _oecc57
#define OEMCrypto_CreateUsageTableHeader      _oecc61
#define OEMCrypto_LoadUsageTableHeader        _oecc62
#define OEMCrypto_CreateNewUsageEntry         _oecc63
#define OEMCrypto_LoadUsageEntry              _oecc64
#define OEMCrypto_UpdateUsageEntry            _oecc65
#define OEMCrypto_DeactivateUsageEntry        _oecc66
#define OEMCrypto_ShrinkUsageTableHeader      _oecc67
#define OEMCrypto_MoveEntry                   _oecc68
#define OEMCrypto_CopyOldUsageEntry           _oecc69
#define OEMCrypto_CreateOldUsageEntry         _oecc70
#define OEMCrypto_GetAnalogOutputFlags        _oecc71
#define OEMCrypto_LoadTestKeybox              _oecc78
#define OEMCrypto_LoadEntitledContentKeys_V14 _oecc79
#define OEMCrypto_SelectKey                   _oecc81
#define OEMCrypto_LoadKeys_V14                _oecc82
#define OEMCrypto_LoadKeys                    _oecc83
#define OEMCrypto_SetSandbox                  _oecc84
#define OEMCrypto_ResourceRatingTier          _oecc85
#define OEMCrypto_SupportsDecryptHash         _oecc86
#define OEMCrypto_InitializeDecryptHash       _oecc87
#define OEMCrypto_SetDecryptHash              _oecc88
#define OEMCrypto_GetHashErrorCode            _oecc89
#define OEMCrypto_BuildInformation            _oecc90
#define OEMCrypto_RefreshKeys                 _oecc91
#define OEMCrypto_LoadEntitledContentKeys     _oecc92
#define OEMCrypto_CopyBuffer                  _oecc93
#define OEMCrypto_MaximumUsageTableHeaderSize _oecc94
#define OEMCrypto_GenerateDerivedKeys         _oecc95
#define OEMCrypto_PrepAndSignLicenseRequest   _oecc96
#define OEMCrypto_PrepAndSignRenewalRequest   _oecc97
#define OEMCrypto_PrepAndSignProvisioningRequest _oecc98
#define OEMCrypto_LoadLicense                 _oecc99
#define OEMCrypto_LoadRenewal                 _oecc101
#define OEMCrypto_LoadProvisioning            _oecc102
#define OEMCrypto_LoadOEMPrivateKey           _oecc103
#define OEMCrypto_GetOEMPublicCertificate     _oecc104
#define OEMCrypto_DecryptCENC                 _oecc105
#define OEMCrypto_LoadDRMPrivateKey           _oecc107
#define OEMCrypto_MinorAPIVersion             _oecc108
// clang-format on

/// @addtogroup initcontrol
/// @{

/**
 * This tells OEMCrypto which sandbox the current process belongs to. Any
 * persistent memory used to store the generation number should be associated
 * with this sandbox id. OEMCrypto can assume that this sandbox will be tied
 * to the current process or VM until OEMCrypto_Terminate is called. See the
 * section "VM and Sandbox Support" above for more details.
 *
 * If OEMCrypto does not support sandboxes, it will return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED. On most platforms, this function will
 * just return OEMCrypto_ERROR_NOT_IMPLEMENTED. If OEMCrypto supports
 * sandboxes, this function returns OEMCrypto_SUCCESS on success, and
 * OEMCrypto_ERROR_UNKNOWN_FAILURE on failure.
 *
 * The CDM layer will call OEMCrypto_SetSandbox once before
 * OEMCrypto_Initialize. After this function is called and returns success,
 * it will be OEMCrypto's responsibility to keep calls to usage table
 * functions separate, and to accept a call to OEMCrypto_Terminate for each
 * sandbox.
 *
 * @param[in] sandbox_id: a short string unique to the current sandbox.
 * @param[in] sandbox_id_length: length of sandbox_id.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INIT_FAILED failed to initialize crypto hardware
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED sandbox functionality not supported
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system. It is called once before
 *   OEMCrypto_Initialize.
 *
 * @version
 *   This method is new in version 15 of the API.
 */
OEMCryptoResult OEMCrypto_SetSandbox(const uint8_t* sandbox_id,
                                     size_t sandbox_id_length);

/**
 * Initialize the crypto firmware/hardware.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INIT_FAILED failed to initialize crypto hardware
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system.
 *
 * @version
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_Initialize(void);

/**
 * Closes the crypto operation and releases all related resources.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_TERMINATE_FAILED failed to de-initialize crypto
 *         hardware
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system. No other functions will be called before the
 *   system is re-initialized.
 *
 * @version
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_Terminate(void);

/// @}

/// @addtogroup keyladder
/// @{
/**
 * Open a new crypto security engine context. The security engine hardware
 * and firmware shall acquire resources that are needed to support the
 * session, and return a session handle that identifies that session in
 * future calls.
 *
 * This function shall call  ODK_InitializeSessionValues to initialize the
 * session's clock values, timer values, and nonce values.
 * ODK_InitializeSessionValues is described in the document "License Duration
 * and Renewal", to initialize the session's clock values.
 *
 * @param[out] session: an opaque handle that the crypto firmware uses to
 *    identify the session.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_TOO_MANY_SESSIONS failed because too many sessions
 *         are open
 * @retval OEMCrypto_ERROR_OPEN_SESSION_FAILED there is a resource issue or the
 *         security engine is not properly initialized.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Initialization Function" and will not be called
 *   simultaneously with any other function, as if the CDM holds a write lock
 *   on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION* session);

/**
 * Closes the crypto security engine session and frees any associated
 * resources. If this session is associated with a Usage Entry, all resident
 * memory associated with it will be freed. It is the CDM layer's
 * responsibility to call OEMCrypto_UpdateUsageEntry before closing the
 * session.
 *
 * @param[in] session: handle for the session to be closed.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_SESSION no open session with that id.
 * @retval OEMCrypto_ERROR_CLOSE_SESSION_FAILED illegal/unrecognized handle or
 *         the security engine is not properly initialized.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Initialization Function" and will not be called
 *   simultaneously with any other function, as if the CDM holds a write lock
 *   on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_CloseSession(OEMCrypto_SESSION session);

/**
 * Generates three secondary keys, mac_key[server], mac_key[client],  and
 * encrypt_key, for handling signing and content key decryption under the
 * license server protocol for CENC.
 *
 * Refer to the Key Derivation section above for more details. This function
 * computes the AES-128-CMAC of the enc_key_context and stores it in secure
 * memory as the encrypt_key. It then computes four cycles of AES-128-CMAC of
 * the mac_key_context and stores it in the mac_keys -- the first two cycles
 * generate the mac_key[server] and the second two cycles generate the
 * mac_key[client]. These two keys will be stored until the next call to
 * OEMCrypto_LoadKeys(). The device key from the keybox is used as the key
 * for the AES-128-CMAC.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] mac_key_context: pointer to memory containing context data for
 *    computing the HMAC generation key.
 * @param[in] mac_key_context_length: length of the HMAC key context data, in
 *    bytes.
 * @param[in] enc_key_context: pointer to memory containing context data for
 *    computing the encryption key.
 * @param[in] enc_key_context_length: length of the encryption key context data,
 *    in bytes.
 *
 * Results:
 *   mac_key[server]: the 256 bit mac key is generated and stored in secure
 *   memory.
 *   mac_key[client]: the 256 bit mac key is generated and stored in secure
 *   memory.
 *   enc_key: the 128 bit encryption key is generated and stored in secure
 *   memory.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support mac_key_context and enc_key_context sizes as
 *   described in the section OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffers are
 *   too large.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 12.
 */
OEMCryptoResult OEMCrypto_GenerateDerivedKeys(
    OEMCrypto_SESSION session, const OEMCrypto_SharedMemory* mac_key_context,
    size_t mac_key_context_length,
    const OEMCrypto_SharedMemory* enc_key_context,
    size_t enc_key_context_length);

/**
 * Generates three secondary keys, mac_key[server], mac_key[client] and
 * encrypt_key, for handling signing and content key decryption under the
 * license server protocol for CENC.
 *
 * This function is similar to OEMCrypto_GenerateDerivedKeys, except that it
 * uses a session key to generate the secondary keys instead of the Widevine
 * Keybox device key. These three keys will be stored in secure memory until
 * the next call to LoadLicense or LoadProvisioning.
 *
 * If the session's private key is an RSA key, then the session key is passed
 * in encrypted by the device RSA public key as the derivation_key, and must
 * be decrypted with the RSA private key before use.
 *
 * If the sesion's private key is an ECC key, then the session key is the
 * SHA256 of the shared secret key calculated by ECDH between the device's
 * ECC private key and the derivation_key. See the document "OEMCrypto
 * Elliptic Curve Support" for details.
 *
 * Once the enc_key and mac_keys have been generated, all calls to LoadKeys
 * or LoadLicense proceed in the same manner for license requests using RSA
 * or using a Widevine keybox token.
 *
 * @verification
 *   If the RSA key's allowed_schemes is not kSign_RSASSA_PSS, then no keys are
 *   derived and the error OEMCrypto_ERROR_INVALID_RSA_KEY is returned. An RSA
 *   key cannot be used for both deriving session keys and also for PKCS1
 *   signatures.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] derivation_key: session key, encrypted with the public RSA key
 *    (from the DRM certifcate) using RSA-OAEP.
 * @param[in] derivation_key_length: length of derivation_key, in bytes.
 * @param[in] mac_key_context: pointer to memory containing context data for
 *    computing the HMAC generation key.
 * @param[in] mac_key_context_length: length of the HMAC key context data, in
 *    bytes.
 * @param[in] enc_key_context: pointer to memory containing context data for
 *    computing the encryption key.
 * @param[in] enc_key_context_length: length of the encryption key context data,
 *    in bytes.
 *
 * Results:
 *   mac_key[server]: the 256 bit mac key is generated and stored in secure
 *   memory.
 *   mac_key[client]: the 256 bit mac key is generated and stored in secure
 *   memory.
 *   enc_key: the 128 bit encryption key is generated and stored in secure
 *   memory.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_DEVICE_NOT_RSA_PROVISIONED
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support mac_key_context and enc_key_context sizes as
 *   described in the section OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffers are
 *   too large.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_DeriveKeysFromSessionKey(
    OEMCrypto_SESSION session, const uint8_t* derivation_key,
    size_t derivation_key_length, const OEMCrypto_SharedMemory* mac_key_context,
    size_t mac_key_context_length,
    const OEMCrypto_SharedMemory* enc_key_context,
    size_t enc_key_context_length);

/**
 * Generates a 32-bit nonce to detect possible replay attack on the key
 * control block. The nonce is stored in secure memory and will be used in
 * the license or provisioning request.
 *
 * Because the nonce will be used to prevent replay attacks, it is desirable
 * that a rogue application cannot rapidly call this function until a
 * repeated nonce is created randomly. This is called a nonce flood. With
 * this in mind, if more than 200 nonces are requested within one second,
 * OEMCrypto will return an error after the 200th and not generate any more
 * nonces for the rest of the second. After an error, if the application
 * waits at least one second before requesting more nonces, then OEMCrypto
 * will reset the error condition and generate valid nonces again.
 *
 * The nonce should be stored in the session's ODK_NonceValue field by
 * calling the function ODK_SetNonceValue(&nonce_values, nonce). The ODK
 * functions are documented in "Widevine Core Message Serialization".
 *
 * This function shall only be called at most once per open session. It shall
 * only be called before signing either a provisioning request or a license
 * request. If an attempt is made to generate a nonce while in the wrong
 * state, an error of OEMCrypto_ERROR_INVALID_CONTEXT is returned.
 *
 * @param[in] session: handle for the session to be used.
 * @param[out] nonce: pointer to memory to receive the computed nonce.
 *
 * Results:
 *   nonce: the nonce is also stored in secure memory.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Initialization Function" and will not be called
 *   simultaneously with any other function, as if the CDM holds a write lock
 *   on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_GenerateNonce(OEMCrypto_SESSION session,
                                        uint32_t* nonce);

/**
 * OEMCrypto will use ODK_PrepareCoreLicenseRequest to prepare the core
 * message. If it returns OEMCrypto_SUCCESS, then OEMCrypto shall sign the
 * the message body using the DRM certificate's private key. If it returns an
 * error, the error should be returned by OEMCrypto to the CDM layer.
 * ODK_PrepareCoreLicenseRequest is described in the document "Widevine Core
 * Message Serialization".
 *
 * The message body is the buffer starting at message + core_message_size,
 * and with length message_length - core_message_size. The reason OEMCrypto
 * only signs the message body and not the entire message is to allow a v16
 * device to request a license from a v15 license server.
 *
 * If the session's private RSA key has an "allowed_schemes" bit field, then
 * it must be 0x1 (RSASSA-PSS with SHA1). If not, then an error of
 * OEMCrypto_ERROR_SIGNATURE_FAILURE shall be returned.
 *
 * OEMCrypto shall compute a hash of the core license request. The core
 * license request is the buffer starting at message and with length
 * core_message_size. The hash will be saved with the session and verified
 * that it matches a hash in the license response.
 *
 * OEMCrypto shall also call the function ODK_InitializeClockValues,
 * described in the document "License Duration and Renewal", to initialize
 * the session's clock values.
 *
 * Refer to the Signing Messages Sent to a Server section above for more
 * details about the signature algorithm.
 *
 * NOTE: if signature pointer is null and/or input signature_length is zero,
 * this function returns OEMCrypto_ERROR_SHORT_BUFFER and sets output
 * signature_length to the size needed to receive the output signature.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in,out] message: Pointer to memory for the entire message. Modified by
 *    OEMCrypto via the ODK library.
 * @param[in] message_length: length of the entire message buffer.
 * @param[in,out] core_message_size: length of the core message at the beginning
 *    of the message. (in) size of buffer reserved for the core message, in
 *    bytes. (out) actual length of the core message, in bytes.
 * @param[out] signature: pointer to memory to receive the computed signature.
 * @param[in,out] signature_length: (in) length of the signature buffer, in
 *    bytes. (out) actual length of the signature, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if signature buffer is not large enough
 *         to hold the signature.
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_PrepAndSignLicenseRequest(
    OEMCrypto_SESSION session, uint8_t* message, size_t message_length,
    size_t* core_message_size, uint8_t* signature, size_t* signature_length);

/**
 * OEMCrypto will use ODK_PrepareCoreRenewalRequest, as described in the
 * document "Widevine Core Message Serialization", to prepare the core
 * message.
 *
 * If it returns an error, the error should be returned by OEMCrypto to the
 * CDM layer. If it returns OEMCrypto_SUCCESS, then OEMCrypto computes the
 * signature using the renewal mac key which was delivered in the license via
 * LoadLicense.
 *
 * If nonce_values.api_level is 16, then OEMCrypto shall compute the
 * signature of the entire message using the session's client renewal mac
 * key. The entire message is the buffer starting at message with length
 * message_length.
 *
 * If nonce_values.api_major_version is 15, then OEMCrypto shall compute the
 * signature of the message body using the session's client renewal mac key.
 * The message body is the buffer starting at message+core_message_size with
 * length message_length - core_message_size. If the session has not had a
 * license loaded, it will use the usage entries client mac key to sign the
 * message body.
 *
 * This function generates a HMAC-SHA256 signature using the mac_key[client]
 * for license request signing under the license server protocol for CENC.
 *
 * The key used for signing should be the mac_key[client] that was generated
 * for this session or loaded for this session by OEMCrypto_LoadKeys,
 * OEMCrypto_LoadLicense, or OEMCrypto_LoadUsageEntry.
 *
 * Refer to the Signing Messages Sent to a Server section above for more
 * details.
 *
 * If a usage entry has been loaded, but keys have not been loaded through
 * OEMCrypto_LoadKeys, then the derived mac keys and the keys in the usage
 * entry may be different. In this case, the mac keys specified in the usage
 * entry should be used.
 *
 * NOTE: if signature pointer is null and/or input signature_length is zero,
 * this function returns OEMCrypto_ERROR_SHORT_BUFFER and sets output
 * signature_length to the size needed to receive the output signature.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in,out] message: Pointer to memory for the entire message. Modified by
 *    OEMCrypto via the ODK library.
 * @param[in] message_length: length of the entire message buffer.
 * @param[in,out] core_message_size: length of the core message at the beginning
 *    of the message. (in) size of buffer reserved for the core message, in
 *    bytes. (out) actual length of the core message, in bytes.
 * @param[out] signature: pointer to memory to receive the computed signature.
 * @param[in,out] signature_length: (in) length of the signature buffer, in
 *    bytes. (out) actual length of the signature, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if signature buffer is not large enough
 *         to hold the signature.
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_PrepAndSignRenewalRequest(
    OEMCrypto_SESSION session, uint8_t* message, size_t message_length,
    size_t* core_message_size, uint8_t* signature, size_t* signature_length);

/**
 * OEMCrypto will use OEMCrypto_PrepAndSignProvisioningRequest, as described
 * in the document "Widevine Core Message Serialization", to prepare the core
 * message. If it returns an error, the error should be returned by OEMCrypto
 * to the CDM layer. If it returns OEMCrypto_SUCCESS, then OEMCrypto shall
 * compute the signature of the entire message. The entire message is the
 * buffer starting at message with length message_length.
 *
 * For a device that has a keybox, i.e. Provisioning 2.0, OEMCrypto will sign
 * the request with the session's derived client mac key from the previous
 * call to OEMCrypto_GenerateDerivedKeys.
 *
 * For a device that has an OEM Certificate, i.e. Provisioning 3.0, OEMCrypto
 * will sign the request with the private key associated with the OEM
 * Certificate. The key shall have been loaded by a previous call to
 * OEMCrypto_LoadDRMPrivateKey.
 *
 * Refer to the Signing Messages Sent to a Server section above for more
 * details.
 *
 * NOTE: if signature pointer is null and/or input signature_length is zero,
 * this function returns OEMCrypto_ERROR_SHORT_BUFFER and sets output
 * signature_length to the size needed to receive the output signature.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in,out] message: Pointer to memory for the entire message. Modified by
 *    OEMCrypto via the ODK library.
 * @param[in] message_length: length of the entire message buffer.
 * @param[in,out] core_message_size: length of the core message at the beginning
 *    of the message. (in) size of buffer reserved for the core message, in
 *    bytes. (out) actual length of the core message, in bytes.
 * @param[out] signature: pointer to memory to receive the computed signature.
 * @param[in,out] signature_length: (in) length of the signature buffer, in
 *    bytes. (out) actual length of the signature, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if signature buffer is not large enough
 *         to hold the signature.
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_PrepAndSignProvisioningRequest(
    OEMCrypto_SESSION session, uint8_t* message, size_t message_length,
    size_t* core_message_size, uint8_t* signature, size_t* signature_length);

/**
 * Verify and install a new SRM file. The device shall install the new file
 * only if verification passes. If verification fails, the existing SRM will
 * be left in place. Verification is defined by DCP, and includes
 * verification of the SRM's signature and verification that the SRM version
 * number will not be decreased. See the section HDCP SRM Update above for
 * more details about the SRM. This function is for devices that support HDCP
 * v2.2 or higher and wish to receive 4k content.
 *
 * @param[in] bufer: buffer containing the SRM
 * @param[in] buffer_length: length of the SRM, in bytes.
 *
 * @retval OEMCrypto_SUCCESS if the file was valid and was installed.
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT if the SRM version is too low, or
 *         the file is corrupted.
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE If the signature is invalid.
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is too large for the
 *         device.
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   The size of the buffer is determined by the HDCP specification.
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_LoadSRM(const uint8_t* buffer, size_t buffer_length);

/**
 * Install a set of keys for performing decryption in the current session.
 * This function will be deprecated and will only be used for legacy license
 * from a license server that does not yet support the v16 interface.
 *
 * The relevant fields have been extracted from the License Response protocol
 * message, but the entire message and associated signature are provided so
 * the message can be verified (using HMAC-SHA256 with the derived
 * mac_key[server]). If the signature verification fails, ignore all other
 * arguments and return OEMCrypto_ERROR_SIGNATURE_FAILURE. Otherwise, add the
 * keys to the session context.
 *
 * The keys will be decrypted using the current encrypt_key (AES-128-CBC) and
 * the IV given in the KeyObject. Each key control block will be decrypted
 * using the first 128 bits of the corresponding content key (AES-128-CBC)
 * and the IV given in the KeyObject.
 *
 * If its length is not zero, enc_mac_keys will be used to create new
 * mac_keys. After all keys have been decrypted and validated, the new
 * mac_keys are decrypted with the current encrypt_key and the offered IV.
 * The new mac_keys replaces the current mac_keys for future calls to
 * OEMCrypto_RefreshKeys(). The first 256 bits of the mac_keys become the
 * mac_key[server] and the following 256 bits of the mac_keys become the
 * mac_key[client].
 *
 * The mac_key and encrypt_key were generated and stored by the previous call
 * to OEMCrypto_GenerateDerivedKeys() or
 * OEMCrypto_DeriveKeysFromSessionKey(). The nonce was generated and stored
 * in the session's nonce_values by the previous call to
 * OEMCrypto_GenerateNonce().
 *
 * This session's elapsed time clock is started at 0. The clock will be used
 * in OEMCrypto_DecryptCENC().
 *
 * NOTE: The calling software must have previously established the mac_keys
 * and encrypt_key with a call to OEMCrypto_DeriveKeysFromSessionKey().
 *
 * Refer to the Verification of Messages from a Server section above for more
 * details.
 *
 * If the parameter license_type is OEMCrypto_ContentLicense, then the fields
 * key_id and key_data in an OEMCrypto_KeyObject are loaded in to the
 * content_key_id and content_key_data fields of the key table entry. In this
 * case, entitlement key ids and entitlement key data is left blank.
 *
 * If the parameter license_type is OEMCrypto_EntitlementLicense,  then the
 * fields key_id and key_data in an OEMCrypto_KeyObject are loaded in to the
 * entitlement_key_id and entitlement_key_data fields of the key table entry.
 * In this case, content key ids and content key data will be loaded later
 * with a call to OEMCrypto_LoadEntitledContentKeys().
 *
 * OEMCrypto may assume that the key_id_length is at most 16. However,
 * OEMCrypto shall correctly handle key id lengths from 1 to 16 bytes.
 *
 * OEMCrypto shall handle at least 20 keys per session. This allows a single
 * license to contain separate keys for 3 key rotations (previous interval,
 * current interval, next interval) times 4 content keys (audio, SD, HD, UHD)
 * plus up to 8 keys for watermarks.
 *
 * After a call to OEMCrypto_LoadKeys, oemcrypto should clear the encrypt_key
 * for the session.
 *
 * @verification
 * The following checks should be performed. If any check fails, an error is
 * returned, and none of the keys are loaded.
 *   1. The signature of the message shall be computed, and the API shall
 *      verify the computed signature matches the signature passed in.  If
 *      not, return OEMCrypto_ERROR_SIGNATURE_FAILURE.  The signature
 *      verification shall use a constant-time algorithm (a signature
 *      mismatch will always take the same time as a successful comparison).
 *   2. If there already is a license loaded into this session, return
 *      OEMCrypto_ERROR_LICENSE_RELOAD.
 *   3. The enc_mac_keys substring must either have zero length, or satisfy
 *      the range check. I.e.  (offset < message_length) && (offset + length
 *      <= message_length) && (offset <= offset + length), and offset + length
 *      does not cause an integer overflow. If it does not have zero length,
 *      then enc_mac_keys_iv must not have zero length, and must also satisfy
 *      the range check.  If not, return OEMCrypto_ERROR_INVALID_CONTEXT.  If
 *      the length is zero, then OEMCrypto may assume that the offset is also
 *      zero.
 *   4. The API shall verify that each substring in each KeyObject points to
 *      a location in the message.  I.e.  (offset < message_length) &&
 *      (offset + length <= message_length) && (offset <= offset + length),
 *      and offset + length does not cause an integer overflow, for each of
 *      key_id, key_data_iv, key_data, key_control_iv, key_control. If not,
 *      return OEMCrypto_ERROR_INVALID_CONTEXT.
 *   5. Each key's control block, after decryption, shall have a valid
 *      verification field. If not, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *   6. If any key control block has the Nonce_Enabled bit set, that key's
 *      Nonce field shall match a nonce in the cache.  If not, return
 *      OEMCrypto_ERROR_INVALID_NONCE.  If there is a match, remove that
 *      nonce from the cache.  Note that all the key control blocks in a
 *      particular call shall have the same nonce value.
 *   7. If any key control block has the Require_AntiRollback_Hardware bit
 *      set, and the device does not protect the usage table from rollback,
 *      then do not load the keys and return OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *   8. If the key control block has a nonzero Replay_Control, then the
 *      verification described below is also performed.
 *   9. If the key control block has the bit SRMVersionRequired is set, then
 *      the verification described below is also performed.  If the SRM
 *      requirement is not met, then the key control block's HDCP_Version
 *      will be changed to 0xF - local display only.
 *   10. If key_array_length == 0, then return
 *      OEMCrypto_ERROR_INVALID_CONTEXT.
 *   11. If this session is associated with a usage table entry, and that
 *      entry is marked as "inactive" (either kInactiveUsed or
 *      kInactiveUnused), then the keys are not loaded, and the error
 *      OEMCrypto_ERROR_LICENSE_INACTIVE is returned.
 *   12. The data in enc_mac_keys_iv is not identical to the 16 bytes before
 *      enc_mac_keys.  If it is, return OEMCrypto_ERROR_INVALID_CONTEXT.
 * Usage Table and Provider Session Token (pst)
 * If a key control block has a nonzero value for Replay_Control, then all
 * keys in this license will have the same value for Replay_Control. In this
 * case, the following additional checks are performed.
 *   - The substring pst must have nonzero length and must satisfy the range
 *      check described above.  If not, return
 *      OEMCrypto_ERROR_INVALID_CONTEXT.
 *   - The session must be associated with a usage table entry, either
 *      created via OEMCrypto_CreateNewUsageEntry or loaded via
 *      OEMCrypto_LoadUsageEntry.
 *   - If Replay_Control is 1 = Nonce_Required, then OEMCrypto will perform a
 *      nonce check as described above.   OEMCrypto will verify that the
 *      usage entry is newly created with OEMCrypto_CreateNewUsageEntry.  If
 *      an existing entry was reloaded, an error
 *      OEMCrypto_ERROR_INVALID_CONTEXT is returned and no keys are loaded.
 *      OEMCrypto will then copy the pst and the mac keys to the usage entry,
 *      and set the status to Unused. This Replay_Control prevents the
 *      license from being loaded more than once, and will be used for online
 *      streaming.
 *   - If Replay_Control is 2 = "Require existing Session Usage table entry
 *      or Nonce",  then OEMCrypto will behave slightly differently on the
 *      first call to LoadKeys for this license.
 *        * If the usage entry was created with OEMCrypto_CreateNewUsageEntry
 *           for this session, then OEMCrypto will verify the nonce for each
 *           key. OEMCrypto will copy the pst and mac keys to the usage
 *           entry.  The license received time of the entry will be updated
 *           to the current time, and the status will be set to Unused.
 *        * If the usage entry was loaded with OEMCrypto_LoadUsageEntry for
 *           this session, then OEMCrypto will NOT verify the nonce for each
 *           key.  Instead, it will verify that the pst passed in matches
 *           that in the entry.  Also, the entry's mac keys will be verified
 *           against the current session's mac keys.  This allows an offline
 *           license to be reloaded but maintain continuity of the playback
 *           times from one session to the next.
 *        * If the nonce is not valid and a usage entry was not loaded, the
 *           return error is OEMCrypto_ERROR_INVALID_NONCE.
 *        * If the loaded usage entry has a pst that does not match,
 *           OEMCrypto returns the error OEMCrypto_ERROR_WRONG_PST.
 *        * If the loaded usage entry has mac keys that do not match the
 *           license, OEMCrypto returns the error OEMCrypto_ERROR_WRONG_KEYS.
 * Note: If LoadKeys updates the mac keys, then the new updated mac keys will
 * be used with the Usage Entry --   i.e. the new keys are stored in the
 * usage table when creating a new entry, or the new keys are verified
 * against those in the usage table if there is an existing entry. If
 * LoadKeys does not update the mac keys, the existing session mac keys are
 * used.
 *
 * Sessions that are associated with an entry will need to be able to update
 * and verify the status of the entry, and the time stamps in the entry.
 *
 * Devices that do not support the Usage Table will return
 * OEMCrypto_ERROR_INVALID_CONTEXT if the Replay_Control is nonzero.
 *
 * Timer Update
 * After verification, the session's clock and timer values are updated by
 * calling the function ODK_InitializeV15Values as described in the document
 * "Widevine Core Message Serialization".
 *
 * SRM Restriction Data
 *
 * If any key control block has the flag SRMVersionRequired set, then the
 * following verification is also performed.
 *
 *   1. The substring srm_restriction_data must have nonzero length and must
 *      satisfy the range check described above.  If not, return
 *      OEMCrypto_ERROR_INVALID_CONTEXT.
 *   2. The first 8 bytes of srm_restriction_data must match the string
 *      "HDCPDATA".  If not, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *   3. The next 4 bytes of srm_restriction_data will be converted from
 *      network byte order.  If the current SRM installed on the device has a
 *      version number less than this, then the SRM requirement is not met.
 *      If the device does not support SRM files, or OEMCrypto cannot
 *      determine the current SRM version number, then the SRM requirement is
 *      not met.
 * Note: if the current SRM version requirement is not met, LoadKeys will
 * still succeed and the keys will be loaded. However, those keys with the
 * SRMVersionRequired bit set will have their HDCP_Version increased to 0xF -
 * local display only. Any future call to SelectKey for these keys while
 * there is an external display will return OEMCrypto_ERROR_INSUFFICIENT_HDCP
 * at that time.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] message: pointer to memory containing message to be verified.
 * @param[in] message_length: length of the message, in bytes.
 * @param[in] signature: pointer to memory containing the signature.
 * @param[in] signature_length: length of the signature, in bytes.
 * @param[in] enc_mac_keys_iv: IV for decrypting new mac_key. Size is 128 bits.
 * @param[in] enc_mac_keys: encrypted mac_keys for generating new mac_keys.
 *    Size is 512 bits.
 * @param[in] key_array_length: number of keys present.
 * @param[in] key_array: set of keys to be installed.
 * @param[in] pst: the Provider Session Token.
 * @param[in] srm_restriction_data: optional data specifying the minimum SRM
 *    version.
 * @param[in] license_type: specifies if the license contains content keys or
 *    entitlement keys.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_NONCE
 * @retval OEMCrypto_ERROR_TOO_MANY_KEYS
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_LICENSE_RELOAD
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_LoadKeys(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length,
    OEMCrypto_Substring enc_mac_keys_iv, OEMCrypto_Substring enc_mac_keys,
    size_t key_array_length, const OEMCrypto_KeyObject* key_array,
    OEMCrypto_Substring pst, OEMCrypto_Substring srm_restriction_data,
    OEMCrypto_LicenseType license_type);

/**
 * Install a set of keys for performing decryption in the current session.
 *
 * First, OEMCrypto shall verify the signature of the message using
 * HMAC-SHA256 with the derived mac_key[server]. The signature verification
 * shall use a constant-time algorithm (a signature mismatch will always take
 * the same time as a successful comparison). The signature is over the
 * entire message buffer starting at message with length message_length. If
 * the signature verification fails, ignore all other arguments and return
 * OEMCrypto_ERROR_SIGNATURE_FAILURE. Otherwise, add the keys to the session
 * context.
 *
 * NOTE: The calling software must have previously established the mac_keys
 * and encrypt_key with a call to OEMCrypto_DeriveKeysFromSessionKey().
 *
 * Refer to the Verification of Messages from a Server section above for more
 * details.
 *
 * The function ODK_ParseLicense is called to parse the message. If it
 * returns an error, OEMCrypto shall return that error to the CDM layer. The
 * function ODK_ParseLicense is described in the document "Widevine Core
 * Message Serialization".
 *
 * Below, all fields are found in the struct ODK_ParsedLicense parsed_license
 * returned by ODK_ParseLicense.
 *
 * The keys will be decrypted using the current encrypt_key (AES-128-CBC) and
 * the IV given in the KeyObject. Each key control block will be decrypted
 * using the first 128 bits of the corresponding content key (AES-128-CBC)
 * and the IV given in the KeyObject.
 *
 * If its length is not zero, enc_mac_keys will be used to create new
 * mac_keys. After all keys have been decrypted and validated, the new
 * mac_keys are decrypted with the current encrypt_key and the offered IV.
 * The new mac_keys replaces the current mac_keys for future signing renewal
 * requests and loading renewal responses. The first 256 bits of the mac_keys
 * become the mac_key[server] and the following 256 bits of the mac_keys
 * become the mac_key[client]. If enc_mac_keys is null, then there will not
 * be a call to OEMCrypto_LoadRenewal for this session and the current
 * mac_keys may be deleted.
 *
 * If the field license_type is OEMCrypto_ContentLicense, then the fields
 * key_id and key_data in an OEMCrypto_KeyObject are loaded in to the
 * content_key_id and content_key_data fields of the key table entry. In this
 * case, entitlement key ids and entitlement key data is left blank.
 *
 * If the field license_type is OEMCrypto_EntitlementLicense,  then the
 * fields key_id and key_data in an OEMCrypto_KeyObject are loaded in to the
 * entitlement_key_id and entitlement_key_data fields of the key table entry.
 * In this case, content key ids and content key data will be loaded later
 * with a call to OEMCrypto_LoadEntitledContentKeys().
 *
 * OEMCrypto may assume that the key_id_length is at most 16. However,
 * OEMCrypto shall correctly handle key id lengths from 1 to 16 bytes.
 *
 * OEMCrypto shall handle multiple keys, as described in the section on
 * Resource Rating Tiers in this document.
 *
 * After a call to OEMCrypto_LoadLicense, oemcrypto should clear the
 * encrypt_key for the session.
 *
 * @verification
 * The following checks should be performed. If any check fails, an error is
 * returned, and none of the keys are loaded.
 *   13. The signature of the message shall be computed, and the API shall
 *      verify the computed signature matches the signature passed in.  If
 *      not, return OEMCrypto_ERROR_SIGNATURE_FAILURE.  The signature
 *      verification shall use a constant-time algorithm (a signature
 *      mismatch will always take the same time as a successful comparison).
 *   14. If there already is a license loaded into this session, return
 *      OEMCrypto_ERROR_LICENSE_RELOAD.
 *   15. The enc_mac_keys substring must either have zero length, or satisfy
 *      the range check. I.e.  (offset < message_length) && (offset + length
 *      <= message_length) && (offset <= offset + length), and offset + length
 *      does not cause an integer overflow. If it does not have zero length,
 *      then enc_mac_keys_iv must not have zero length, and must also satisfy
 *      the range check.  If not, return OEMCrypto_ERROR_INVALID_CONTEXT.  If
 *      the length is zero, then OEMCrypto may assume that the offset is also
 *      zero.
 *   16. The API shall verify that each substring in each KeyObject points to
 *      a location in the message.  I.e.  (offset < message_length) &&
 *      (offset + length <= message_length) && (offset <= offset + length),
 *      and offset + length does not cause an integer overflow, for each of
 *      key_id, key_data_iv, key_data, key_control_iv, key_control. If not,
 *      return OEMCrypto_ERROR_INVALID_CONTEXT.
 *   17. Each key's control block, after decryption, shall have a valid
 *      verification field. If not, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *   18. If any key control block has the Nonce_Enabled bit set, that key's
 *      Nonce field shall match a nonce in the cache.  If not, return
 *      OEMCrypto_ERROR_INVALID_NONCE.  If there is a match, remove that
 *      nonce from the cache.  Note that all the key control blocks in a
 *      particular call shall have the same nonce value.
 *   19. If any key control block has the Require_AntiRollback_Hardware bit
 *      set, and the device does not protect the usage table from rollback,
 *      then do not load the keys and return OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *   20. If the key control block has a nonzero Replay_Control, then the
 *      verification described below is also performed.
 *   21. If the key control block has the bit SRMVersionRequired is set, then
 *      the verification described below is also performed.  If the SRM
 *      requirement is not met, then the key control block's HDCP_Version
 *      will be changed to 0xF - local display only.
 *   22. If key_array_length == 0, then return
 *      OEMCrypto_ERROR_INVALID_CONTEXT.
 *   23. If this session is associated with a usage table entry, and that
 *      entry is marked as "inactive" (either kInactiveUsed or
 *      kInactiveUnused), then the keys are not loaded, and the error
 *      OEMCrypto_ERROR_LICENSE_INACTIVE is returned.
 *   24. The data in enc_mac_keys_iv is not identical to the 16 bytes before
 *      enc_mac_keys.  If it is, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *
 * Usage Table and Provider Session Token (pst)
 * The function ODK_ParseLicense takes several parameters that may need more
 * explanation.
 * The parameter usage_entry_present shall be set to true if a usage entry
 * was created or loaded for this session. This parameter is used by
 * ODK_ParseLicense for usage entry verification.
 * The parameter initial_license_load shall be false if the usage entry was
 * loaded. If there is no usage entry or if the usage entry was created with
 * OEMCrypto_CreateNewUsageEntry, then initial_license_load shall be true.
 * If a usage entry is present, then it shall be verified after the call to
 * ODK_ParseLicense.
 * If initial_license_load is true:
 *   1. OEMCrypto shall copy the PST from the parsed license to the usage
 *      entry.
 *   2. OEMCrypto shall verify that the server and client mac keys were
 *      updated by the license. The server and client mac keys shall be
 *      copied to the usage entry.
 * If initial_license_load is false:
 *   1. OEMCrypto shall verify the PST from the parsed license matches that
 *      in the usage entry. If not, then an error OEMCrypto_ERROR_WRONG_PST
 *      is returned.
 *   2. OEMCrypto shall verify that the server and client mac keys were
 *      updated by the license. OEMCrypto shall verify that the server and
 *      client mac keys match those in the usage entry. If not the error
 *      OEMCrypto_ERROR_WRONG_KEYS is returned.
 * If a key control block has a nonzero value for Replay_Control, then all
 * keys in this license will have the same value for Replay_Control. In this
 * case, the following additional checks are performed.
 *   - The substring pst must have nonzero length and must satisfy the range
 *      check described above.  If not, return
 *      OEMCrypto_ERROR_INVALID_CONTEXT.
 *   - The session must be associated with a usage table entry, either
 *      created via OEMCrypto_CreateNewUsageEntry or loaded via
 *      OEMCrypto_LoadUsageEntry.
 *   - If Replay_Control is 1 = Nonce_Required, then OEMCrypto will perform a
 *      nonce check as described above.   OEMCrypto will verify that the
 *      usage entry is newly created with OEMCrypto_CreateNewUsageEntry.  If
 *      an existing entry was reloaded, an error
 *      OEMCrypto_ERROR_INVALID_CONTEXT is returned and no keys are loaded.
 *      OEMCrypto will then copy the pst and the mac keys to the usage entry,
 *      and set the status to Unused. The license received time of the entry
 *      will be updated to the current time, and the status will be set to
 *      Unused. This Replay_Control prevents the license from being loaded
 *      more than once, and will be used for online streaming.
 *   - If Replay_Control is 2 = "Require existing Session Usage table entry
 *      or Nonce",  then OEMCrypto will behave slightly differently on the
 *      first call to LoadKeys for this license.
 *        * If the usage entry was created with OEMCrypto_CreateNewUsageEntry
 *           for this session, then OEMCrypto will verify the nonce for each
 *           key. OEMCrypto will copy the pst and mac keys to the usage
 *           entry.  The license received time of the entry will be updated
 *           to the current time, and the status will be set to Unused.
 *        * If the usage entry was loaded with OEMCrypto_LoadUsageEntry for
 *           this session, then OEMCrypto will NOT verify the nonce for each
 *           key.  Instead, it will verify that the pst passed in matches
 *           that in the entry.  Also, the entry's mac keys will be verified
 *           against the current session's mac keys.  This allows an offline
 *           license to be reloaded but maintain continuity of the playback
 *           times from one session to the next.
 *        * If the nonce is not valid and a usage entry was not loaded, the
 *           return error is OEMCrypto_ERROR_INVALID_NONCE.
 *        * If the loaded usage entry has a pst that does not match,
 *           OEMCrypto returns the error OEMCrypto_ERROR_WRONG_PST.
 *        * If the loaded usage entry has mac keys that do not match the
 *           license, OEMCrypto returns the error OEMCrypto_ERROR_WRONG_KEYS.
 * Note: If LoadKeys updates the mac keys, then the new updated mac keys will
 * be used with the Usage Entry --   i.e. the new keys are stored in the
 * usage table when creating a new entry, or the new keys are verified
 * against those in the usage table if there is an existing entry. If
 * LoadKeys does not update the mac keys, the existing session mac keys are
 * used.
 * Sessions that are associated with an entry will need to be able to update
 * and verify the status of the entry, and the time stamps in the entry.
 * Devices that do not support the Usage Table will return
 * OEMCrypto_ERROR_INVALID_CONTEXT if the Replay_Control is nonzero.
 * SRM Restriction Data
 * If any key control block has the flag SRMVersionRequired set, then the
 * following verification is also performed.
 *   4. The substring srm_restriction_data must have nonzero length and must
 *      satisfy the range check described above.  If not, return
 *      OEMCrypto_ERROR_INVALID_CONTEXT.
 *   5. The first 8 bytes of srm_restriction_data must match the string
 *      "HDCPDATA".  If not, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *   6. The next 4 bytes of srm_restriction_data will be converted from
 *      network byte order.  If the current SRM installed on the device has a
 *      version number less than this, then the SRM requirement is not met.
 *      If the device does not support SRM files, or OEMCrypto cannot
 *      determine the current SRM version number, then the SRM requirement is
 *      not met.
 * Note: if the current SRM version requirement is not met, LoadKeys will
 * still succeed and the keys will be loaded. However, those keys with the
 * SRMVersionRequired bit set will have their HDCP_Version increased to 0xF -
 * local display only. Any future call to SelectKey for these keys while
 * there is an external display will return OEMCrypto_ERROR_INSUFFICIENT_HDCP
 * at that time.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] message: pointer to memory containing data.
 * @param[in] message_length: length of the message, in bytes.
 * @param[in] core_message_length: length of the core submessage, in bytes.
 * @param[in] signature: pointer to memory containing the signature.
 * @param[in] signature_length: length of the signature, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_NONCE
 * @retval OEMCrypto_ERROR_TOO_MANY_KEYS
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_LICENSE_RELOAD
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_LoadLicense(OEMCrypto_SESSION session,
                                      const uint8_t* message,
                                      size_t message_length,
                                      size_t core_message_length,
                                      const uint8_t* signature,
                                      size_t signature_length);

/**
 * Load content keys into a session which already has entitlement keys
 * loaded. This function will only be called for a session after a call to
 * OEMCrypto_LoadKeys with the parameter type license_type equal to
 * OEMCrypto_EntitlementLicense. This function may be called multiple times
 * for the same session.
 *
 * If the session does not have license_type equal to
 * OEMCrypto_EntitlementLicense, return OEMCrypto_ERROR_INVALID_CONTEXT and
 * perform no work.
 *
 * For each key object in key_array, OEMCrypto shall look up the entry in the
 * key table with the corresponding entitlement_key_id.
 *
 *   1. If no entry is found, return OEMCrypto_KEY_NOT_ENTITLED.
 *   2. If the entry already has a content_key_id and content_key_data, that
 *      id and data are erased.
 *   3. The content_key_id from the key_array is copied to the entry's
 *      content_key_id.
 *   4. The content_key_data decrypted using the entitlement_key_data as a
 *      key for AES-256-CBC with an IV of content_key_data_iv.  Wrapped
 *      content is padded using PKCS#7 padding. Notice that the entitlement
 *      key will be an AES 256 bit key.  The clear content key data will be
 *      stored in the entry's content_key_data.
 * Entries in the key table that do not correspond to anything in the
 * key_array are not modified or removed.
 *
 * For devices that use a hardware key ladder, it may be more convenient to
 * store the encrypted content key data in the key table, and decrypt it when
 * the function SelectKey is called.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] message: pointer to memory containing message to be verified.
 * @param[in] message_length: length of the message, in bytes.
 * @param[in] key_array_length: number of keys present.
 * @param[in] key_array: set of key updates.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_KEY_NOT_ENTITLED
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 14.
 */
OEMCryptoResult OEMCrypto_LoadEntitledContentKeys(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    size_t key_array_length,
    const OEMCrypto_EntitledContentKeyObject* key_array);

/**
 * Updates the license clock values to allow playback to continue. This
 * function is being deprecated and is only used for version v15 licenses --
 * i.e. offline license saved before an update or licenses from a server that
 * has not update to the v16 license server SDK.
 *
 * OEMCrypto shall compute the signature of the message using
 * mac_key[server], and shall verify the computed signature matches the
 * signature passed in. If not, return OEMCrypto_ERROR_SIGNATURE_FAILURE. The
 * signature verification shall use a constant-time algorithm (a signature
 * mismatch will always take the same time as a successful comparison).
 *
 * The key control from the first OEMCrypto_KeyRefreshObject in the key_array
 * shall be extracted. If it is encrypted, as described below, it shall be
 * decrypted. The duration from the key control shall be extracted and
 * converted to host byte order. This duration shall be passed to the
 * function ODK_RefreshV15Values as the parameter new_key_duration.
 *
 * If the KeyRefreshObject's key_control_iv has zero length, then the
 * key_control is not encrypted. If the key_control_iv is specified, then
 * key_control is encrypted with the first 128 bits of the corresponding
 * content key.
 *
 * If the KeyRefreshObject's key_id has zero length, then it is an error for
 * the key_control_iv to have nonzero length. OEMCrypto shall return an error
 * of OEMCrypto_ERROR_INVALID_CONTEXT.
 *
 * If the session's license_type is OEMCrypto_ContentLicense, and the
 * KeyRefreshObject's key_id is not null, then the entry in the keytable with
 * the matching content_key_id is used.
 *
 * If the session's license_type is OEMCrypto_EntitlementLicense, and the
 * KeyRefreshObject's key_id is not null, then the entry in the keytable with
 * the matching entitlment_key_id is used.
 *
 * The function ODK_RefreshV15Values shall be called to update the clock
 * values. See the document "Widevine Core Message Serialization" for the
 * documentation of the ODK library functions.
 *
 * If ODK_RefreshV15Values returns
 *
 *   - ODK_SET_TIMER: Success.  The timer should be reset to the specified
 *      timer value.
 *   - ODK_DISABLE_TIMER: Success, but disable timer.  Unlimited playback is
 *      allowed.
 *   - ODK_TIMER_EXPIRED: Set timer as disabled.  Playback is not allowed.
 *   - ODK_STALE_RENEWAL: This renewal is not the most recently signed. It is
 *      rejected. Return this error
 *   - Any other error - OEMCrypto shall pass any other error up to the
 *      caller of OEMCrypto_RefreshKeys.
 *
 * NOTE: OEMCrypto_LoadKeys() must be called first to load the keys into the
 * session.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] message: pointer to memory containing message to be verified.
 * @param[in] message_length: length of the message, in bytes.
 * @param[in] signature: pointer to memory containing the signature.
 * @param[in] signature_length: length of the signature, in bytes.
 * @param[in] num_keys: number of keys present.
 * @param[in] key_array: set of key updates.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_NONCE
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_NO_CONTENT_KEY
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_RefreshKeys(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length, size_t num_keys,
    const OEMCrypto_KeyRefreshObject* key_array);

/**
 * Updates the clock values and resets the renewal timer for the current
 * session.
 *
 * OEMCrypto shall verify the signature of the entire message using the
 * session's renewal mac key for the server. The entire message is the buffer
 * starting at message with length message_length. If the signature does not
 * match, OEMCrypto returns OEMCrypto_ERROR_SIGNATURE_FAILURE.
 *
 * OEMCrypto shall verify that nonce_values.api_major_version is 16. If not,
 * return the error OEMCrypto_ERROR_INVALID_CONTEXT. Legacy licenses will use
 * the function OEMCrypto_RefreshKeys instead of OEMCrypto_LoadRenewal.
 *
 * If the signature passes, OEMCrypto shall use the function
 * ODK_ParseRenewal, as described in the document "Widevine Core Message
 * Serialization" to parse and verify the message. If ODK_ParseRenewal
 * returns an error OEMCrypto returns the error to the CDM layer.
 *
 * The function ODK_ParseRenewal updates the clock values for the session,
 * and may return ODK_SET_TIMER, ODK_DISABLE_TIMER or ODK_TIMER_EXPIRED on
 * success. These values shall be handled by OEMCrypto, as discussed in the
 * document "License Duration and Renewal".
 *
 * NOTE: OEMCrypto_LoadLicense() must be called first to load the keys into
 * the session.
 *
 * @verification
 *   The signature of the message shall be computed using mac_key[server], and
 *   the API shall verify the computed signature matches the signature passed
 *   in. If not, return OEMCrypto_ERROR_SIGNATURE_FAILURE. The signature
 *   verification shall use a constant-time algorithm (a signature mismatch
 *   will always take the same time as a successful comparison).
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] message: pointer to memory containing message to be verified.
 * @param[in] message_length: length of the message, in bytes.
 * @param[in] core_message_length: length of the core submessage, in bytes.
 * @param[in] signature: pointer to memory containing the signature.
 * @param[in] signature_length: length of the signature, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_NONCE
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval ODK_STALE_RENEWAL
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 12.
 */
OEMCryptoResult OEMCrypto_LoadRenewal(OEMCrypto_SESSION session,
                                      const uint8_t* message,
                                      size_t message_length,
                                      size_t core_message_length,
                                      const uint8_t* signature,
                                      size_t signature_length);

/**
 * Returns the decrypted key control block for the given content_key_id. This
 * function is for application developers to debug license server and key
 * timelines. It only returns a key control block if LoadKeys was successful,
 * otherwise it returns OEMCrypto_ERROR_NO_CONTENT_KEY. The developer of the
 * OEMCrypto library must be careful that the keys themselves are not
 * accidentally revealed.
 *
 * Note: returns control block in original, network byte order. If OEMCrypto
 * converts fields to host byte order internally for storage, it should
 * convert them back. Since OEMCrypto might not store the nonce or validation
 * fields, values of 0 may be used instead.
 *
 * @verification
 *   The following checks should be performed.
 *     1. If key_id is null, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *     2. If key_control_block_length is null, return
 *        OEMCrypto_ERROR_INVALID_CONTEXT.
 *     3. If *key_control_block_length is less than the length of a key control
 *        block, set it to the correct value, and return
 *        OEMCrypto_ERROR_SHORT_BUFFER.
 *     4. If key_control_block is null, return OEMCrypto_ERROR_INVALID_CONTEXT.
 *     5. If the specified key has not been loaded, return
 *        OEMCrypto_ERROR_NO_CONTENT_KEY.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] content_key_id: The unique id of the key of interest.
 * @param[in] content_key_id_length: The length of key_id, in bytes. From 1 to
 *    16, inclusive.
 * @param[out] key_control_block: A caller-owned buffer.
 * @param[in,out] key_control_block_length. The length of key_control_block
 *    buffer.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 10.
 */
OEMCryptoResult OEMCrypto_QueryKeyControl(OEMCrypto_SESSION session,
                                          const uint8_t* content_key_id,
                                          size_t content_key_id_length,
                                          uint8_t* key_control_block,
                                          size_t* key_control_block_length);

/// @}

/// @addtogroup decryption
/// @{

/**
 * Select a content key and install it in the hardware key ladder for
 * subsequent decryption operations (OEMCrypto_DecryptCENC()) for this
 * session. The specified key must have been previously "installed" via
 * OEMCrypto_LoadKeys(), OEMCrypto_LoadLicense, or
 * OEMCrypto_LoadEntitledContentKeys().
 *
 * A key control block is associated with the key and the session, and is
 * used to configure the session context. The Key Control data is documented
 * in "Key Control Block Definition".
 *
 * Step 1: Lookup the content key data via the offered key_id. The key data
 * includes the key value, and the key control block.
 *
 * Step 2: Latch the content key into the hardware key ladder. Set permission
 * flags based on the key's control block.
 *
 * Step 3: use the latched content key to decrypt (AES-128-CTR or
 * AES-128-CBC) buffers passed in via OEMCrypto_DecryptCENC(). If the key is
 * 256 bits it will be used for OEMCrypto_Generic_Sign or
 * OEMCrypto_Generic_Verify as specified in the key control block. If the key
 * will be used for OEMCrypto_Generic_Encrypt or OEMCrypto_Generic_Decrypt
 * then the cipher mode will always be OEMCrypto_CipherMode_CBC. Continue to
 * use this key for this session until OEMCrypto_SelectKey() is called again,
 * or until OEMCrypto_CloseSession() is called.
 *
 * @verification
 *   1. If the key id is not found in the keytable for this session, then the
 *      key state is not changed and OEMCrypto shall return
 *      OEMCrypto_ERROR_NO_CONTENT_KEY.
 *   2. If the key control block has the bit Disable_Analog_Output set, then
 *      the device should disable analog video output.  If the device has
 *      analog video output that cannot be disabled, then the key is not
 *      selected, and OEMCrypto_ERROR_ANALOG_OUTPUT is returned. This step is
 *      optional -- SelectKey may return OEMCrypto_SUCCESS and delay the
 *      error until a call to OEMCrypto_DecryptCENC.
 *   3. If the key control block has HDCP required, and the device cannot
 *      enforce HDCP, then the key is not selected, and
 *      OEMCrypto_ERROR_INSUFFICIENT_HDCP is returned. This step is optional
 *      -- SelectKey may return OEMCrypto_SUCCESS and delay the error until a
 *      call to OEMCrypto_DecryptCENC.
 *   4. If the key control block has a nonzero value for HDCP_Version, and
 *      the device cannot enforce at least that version of HDCP, then the key
 *      is not selected, and OEMCrypto_ERROR_INSUFFICIENT_HDCP is returned.
 *
 * @param[in]  session: crypto session identifier.
 * @param[in] content_key_id: pointer to the content Key ID.
 * @param[in] content_key_id_length: length of the content Key ID, in bytes.
 *    From 1 to 16, inclusive.
 * @param[in] cipher_mode: whether the key should be prepared for CTR mode or
 *    CBC mode when used in later calls to DecryptCENC. This should be ignored
 *    when the key is used for Generic Crypto calls.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_KEY_EXPIRED if the session's timer has expired
 * @retval OEMCrypto_ERROR_INVALID_SESSION crypto session ID invalid or not open
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY failed to decrypt device key
 * @retval OEMCrypto_ERROR_NO_CONTENT_KEY failed to decrypt content key
 * @retval OEMCrypto_ERROR_CONTROL_INVALID invalid or unsupported control input
 * @retval OEMCrypto_ERROR_KEYBOX_INVALID cannot decrypt and read from Keybox
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_ANALOG_OUTPUT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_HDCP
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_SelectKey(OEMCrypto_SESSION session,
                                    const uint8_t* content_key_id,
                                    size_t content_key_id_length,
                                    OEMCryptoCipherMode cipher_mode);

/**
 * Decrypts or copies a series of input payloads into output buffers using
 * the session context indicated by the session parameter. The input payload
 * is delivered in the form of samples. The samples are subdivided into
 * subsamples. "Samples" and "subsamples" are defined as in the ISO Common
 * Encryption standard (ISO/IEC 23001-7:2016). The samples parameter contains
 * a list of samples, each of which has its own input and output buffers.
 * Each sample contains a buffers field that contains the input and output
 * buffers in its input_data and output fields, respectively.
 *
 * Each sample contains an array of subsample descriptions in its subsamples
 * field. Each subsample is defined as a number of clear bytes followed by a
 * number of encrypted bytes. Subsamples are consecutive inside the sample;
 * the clear bytes of the second subsample begin immediately after the
 * encrypted bytes of the first subsample. This follows the definition in the
 * ISO-CENC standard.
 *
 * Decryption mode is AES-128-CTR or AES-128-CBC depending on the value of
 * cipher_mode previously passed in to OEMCrypto_SelectKey. For the encrypted
 * portion of subsamples, the content key associated with the session is
 * latched in the active hardware key ladder and is used for the decryption
 * operation. For the clear portion of subsamples, the data is simply copied.
 *
 * After decryption, all the input_data bytes are copied to the location
 * described by the output field. The output field is an
 * OEMCrypto_DestBufferDesc, which could be one of:
 *
 *   1. The structure OEMCrypto_DestBufferDesc contains a pointer to a clear
 *      text buffer.  The OEMCrypto library shall verify that key control
 *      allows data to be returned in clear text.  If it is not authorized,
 *      this method should return an error.
 *   2. The structure OEMCrypto_DestBufferDesc contains a handle to a secure
 *      buffer.
 *   3. The structure OEMCrypto_DestBufferDesc indicates that the data should
 *      be sent directly to the decoder and renderer.
 * Depending on your platform's needs, you may not need to support all three
 * of these options.
 *
 * SINGLE-SAMPLE DECRYPTION AND SINGLE-SUBSAMPLE DECRYPTION:
 *
 * If the OEMCrypto implementation is not able to handle the amount of
 * samples and subsamples passed into it, it should return
 * OEMCrypto_ERROR_BUFFER_TOO_LARGE, in which case the CDM can respond by
 * breaking the samples up into smaller pieces and trying to decrypt each of
 * them individually. It is possible that the CDM will break the samples
 * array up into pieces that are still too large, in which case OEMCrypto may
 * return OEMCrypto_ERROR_BUFFER_TOO_LARGE again.
 *
 * If the OEMCrypto implementation cannot handle multiple samples at once, it
 * may return OEMCrypto_ERROR_BUFFER_TOO_LARGE any time it receives more than
 * one sample in a single call to OEMCrypto_DecryptCENC.
 *
 * Similarly, if the OEMCrypto implementation cannot handle multiple
 * subsamples at once, it may return OEMCrypto_ERROR_BUFFER_TOO_LARGE any
 * time it receives more than one subsample in a single call to
 * OEMCrypto_DecryptCENC.
 *
 * The exact way that the CDM code breaks up the samples array is not
 * guaranteed by this specification. The CDM may break down the array of
 * samples into many arrays each containing one sample. The CDM may break
 * down samples into subsamples and pass individual subsamples into
 * OEMCrypto, just like in OEMCrypto v15. The CDM may break down individual
 * subsamples into smaller subsamples, just like in OEMCrypto v15.
 *
 * If OEMCrypto requests that the CDM break samples into subsamples, the
 * "samples" passed into OEMCrypto_DecryptCENC will no longer be full
 * samples. When a full sample is passed into OEMCrypto_DecryptCENC, the
 * first subsample in the subsample array will have the
 * OEMCrypto_FirstSubsample flag set in its subsample_flags field and the
 * last subsample array will have the OEMCrypto_LastSubsample flag set in its
 * subsample_flags field. If this is not the case, OEMCrypto will need to
 * accumulate more subsamples from successive calls to OEMCrypto_DecryptCENC
 * to receive the full sample.
 *
 * The first subsample in the sample will always have
 * OEMCrypto_FirstSubsample set and the last subsample will always have the
 * OEMCrypto_LastSubsample flag set, even if those subsamples are passed in
 * separate calls to OEMCrypto_DecryptCENC. This is the same as in OEMCrypto
 * v15. The decrypted data will not be used until after the subsample with
 * the flag OEMCrypto_LastSubsample has been sent to OEMCrypto. This can be
 * relied on by OEMCrypto for optimization by not doing decrypt until the
 * last subsample has been received. However, a device that can do decrypt of
 * more than one subsample at a time will always have better performance if
 * it can receive those subsamples in one OEMCrypto_Decrypt call rather than
 * as individual subsamples.
 *
 * Although the exact way that the CDM code breaks up the samples array when
 * it receives OEMCrypto_ERROR_BUFFER_TOO_LARGE is not guaranteed by this
 * specification, here is a sample way it might work:
 *
 *   1. It tries to pass the array of samples to OEMCrypto_DecryptCENC.
 *   2. If OEMCrypto returns OEMCrypto_ERROR_BUFFER_TOO_LARGE, it tries to
 *      pass each sample individually into OEMCrypto_DecryptCENC.
 *   3. If OEMCrypto returns OEMCrypto_ERROR_BUFFER_TOO_LARGE, it tries to
 *      pass the clear and encrypted parts of each subsample individually
 *      into OEMCrypto_DecryptCENC. At this point, (and in the subsequent
 *      steps) it is replicating the behavior of OEMCrypto v15 and lower.
 *   4. If OEMCrypto returns OEMCrypto_ERROR_BUFFER_TOO_LARGE, it breaks each
 *      piece of a subsample into smaller pieces, down to the minimum
 *      subsample size required by the device's resource rating tier. It
 *      passes these pieces into OEMCrypto_DecryptCENC.
 *   5. If OEMCrypto returns OEMCrypto_ERROR_BUFFER_TOO_LARGE, the device has
 *      failed to meet its resource rating tier requirements. It returns an
 *      error.
 * Because this process requires a lot of back-and-forth between the CDM and
 * OEMCrypto, partners are strongly recommended to support decrypting full
 * samples or even multiple samples in their OEMCrypto implementation.
 *
 * ISO-CENC SCHEMES:
 *
 * The ISO Common Encryption standard (ISO/IEC 23001-7:2016) defines four
 * "schemes" that may be used to encrypt content: 'cenc', 'cens', 'cbc1', and
 * 'cbcs'. Starting with v16, OEMCrypto only supports 'cenc' and 'cbcs'. The
 * schemes 'cens' and 'cbc1' are not supported.
 *
 * The decryption mode, either OEMCrypto_CipherMode_CTR or
 * OEMCrypto_CipherMode_CBC, was already specified in the call to
 * OEMCrypto_SelectKey. The encryption pattern is specified by the fields in
 * the parameter pattern. A description of partial encryption patterns for
 * 'cbcs' can be found in the ISO-CENC standard, section 10.4.
 *
 * 'cenc' SCHEME:
 *
 * The 'cenc' scheme is OEMCrypto_CipherMode_CTR without an encryption
 * pattern. All the bytes in the encrypted portion of each subsample are
 * encrypted. In the pattern parameter, both the encrypt and skip fields will
 * be zero.
 *
 * The length of a crypto block in AES-128 is 16 bytes. In the 'cenc' scheme,
 * if an encrypted subsample has a length that is not a multiple of 16 bytes,
 * then all the bytes of the encrypted subsample must be decrypted, but the
 * next encrypted subsample will begin by completing the incomplete crypto
 * block from the previous encrypted subsample. The following diagram
 * provides an example:
 *
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * To help with this, the block_offset field of each subsample will contain
 * the number of bytes the initial crypto block of that subsample should be
 * offset by. In the example above, the block_offset for the first subsample
 * would be 0 and the block_offset for the second subsample would be 12.
 * 'cenc' is the only mode that allows for a nonzero block_offset. This field
 * satisfies 0 <= block_offset < 16.
 *
 * 'cbcs' SCHEME:
 *
 * The 'cbcs' scheme is OEMCrypto_CipherMode_CBC with an encryption pattern.
 * Only some of the bytes in the encrypted portion of each subsample are
 * encrypted. In the pattern parameter, the encrypt and skip fields will
 * usually be non-zero. This mode allows devices to decrypt FMP4 HLS content,
 * SAMPLE-AES HLS content, as well as content using the DASH 'cbcs' scheme.
 *
 * The skip field of OEMCrypto_CENCEncryptPatternDesc may also be zero. If
 * the skip field is zero, then patterns are not in use and all crypto blocks
 * in the encrypted part of the subsample are encrypted. It is not valid for
 * the encrypt field to be zero.
 *
 * The length of a crypto block in AES-128 is 16 bytes. In the 'cbcs' scheme,
 * if the encrypted part of a subsample has a length that is not a multiple
 * of 16 bytes, then the final bytes that do not make up a full crypto block
 * are clear and should never be decrypted. The following diagram provides an
 * example:
 *
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * Whether any given protected block is actually encrypted also depends on
 * the pattern. But the bytes at the end that do not make up a full crypto
 * block will never be encrypted, regardless of what the pattern is. Even if
 * the pattern says to decrypt every protected block, these bytes are clear
 * and should not be decrypted.
 *
 * Of course, if the encrypted subsample has a length that is a multiple of
 * 16 bytes, all the bytes in it are protected, and they may need to be
 * decrypted following the pattern. The following diagram provides an example:
 *
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * INITIALIZATION VECTOR BETWEEN SUBSAMPLES:
 *
 * The IV is specified for the initial subsample in a sample in the iv field
 * of the OEMCrypto_SampleDescription. OEMCrypto is responsible for correctly
 * updating the IV for subsequent subsamples according to the ISO Common
 * Encryption standard (ISO/IEC 23001-7:2016). Section 9.5.2.3 covers 'cenc'
 * and section 9.5.2.5 covers 'cbcs'. A summary of the ISO-CENC behavior
 * follows:
 *
 * For 'cenc', the IV at the end of each subsample carries forward to the
 * next subsample and becomes the IV at the beginning of the next subsample.
 * If the subsample ends on a crypto block boundary, then the IV should be
 * incremented as normal at the end of the crypto block. If the subsample
 * ends in the middle of a crypto block, the same IV should continue to be
 * used until the crypto block is completed in the next subsample. Only
 * increment the IV after the partial crypto block is completed.
 *
 * For 'cbcs', the IV is reset at the beginning of each subsample. Each
 * subsample should start with the IV that was passed into
 * OEMCrypto_DecryptCENC.
 *
 * To phrase it another way: In 'cenc', the encrypted portions of the
 * subsamples can be concatenated to form one continuous ciphertext. In
 * 'cbcs', each encrypted portion of a subsample is a separate ciphertext.
 * Each separate ciphertext begins with the IV specified in the iv field of
 * the OEMCrypto_SampleDescription.
 *
 * INITIALIZATION VECTOR WITHIN SUBSAMPLES:
 *
 * Once it has the IV for each subsample, OEMCrypto is responsible for
 * correctly updating the IV for each crypto block of each encrypted
 * subsample portion, as outlined in the ISO Common Encryption standard
 * (ISO/IEC 23001-7:2016). Section 9.5.1 includes general information about
 * IVs in subsample decryption. A summary of the ISO-CENC behavior follows:
 *
 * For 'cenc', the subsample's IV is the counter value to be used for the
 * initial encrypted block of the subsample. The IV length is the AES block
 * size. For subsequent encrypted AES blocks, OEMCrypto must calculate the IV
 * by incrementing the lower 64 bits (byte 8-15) of the IV value used for the
 * previous block. The counter rolls over to zero when it reaches its maximum
 * value (0xFFFFFFFFFFFFFFFF). The upper 64 bits (byte 0-7) of the IV do not
 * change.
 *
 * For 'cbcs', the subsample's IV is the initialization vector for the
 * initial encrypted block of the subsample. Within each subsample, each
 * crypto block is used as the IV for the next crypto block, as prescribed by
 * AES-CBC.
 *
 * NOTES:
 *
 * If the destination buffer is secure, an offset may be specified.
 * OEMCrypto_DecryptCENC begins storing data buffers.output.secure.offset
 * bytes after the beginning of the secure buffer.
 *
 * If the session has an entry in the Usage Table, then OEMCrypto must update
 * the time_of_last_decrypt. If the status of the entry is "unused", then
 * change the status to "active" and set the time_of_first_decrypt.
 *
 * OEMCrypto cannot assume that the buffers of consecutive samples are
 * consecutive in memory.
 *
 * A subsample may consist entirely of encrypted bytes or clear bytes. In
 * this case, the clear or the encrypted part of the subsample will be zero,
 * indicating that no bytes of that kind appear in the subsample.
 *
 * The ISO-CENC spec implicitly limits both the skip and encrypt values to be
 * 4 bits, so they are at most 15.
 *
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * If OEMCrypto assembles all of the encrypted subsample portions into a
 * single buffer and then decrypts it in one pass, it can assume that the
 * block offset is 0.
 *
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * @verification
 * The total size of all the subsamples cannot exceed the total size of the
 * input buffer. OEMCrypto integrations should validate this and return
 * OEMCrypto_ERROR_UNKNOWN_FAILURE if the subsamples are larger than the
 * input buffer. No decryption should be performed in this case.
 * If the subsamples all contain only clear bytes, then no further
 * verification is performed. This call shall copy clear data even when there
 * are no keys loaded, or there is no selected key.
 * If this is the first use of a key for this session, then OEMCrypto shall
 * call ODK_AttemptFirstPlayback to update the session's clock values and
 * verify playback is allowed. If this is not the first use of a key for this
 * session, then OEMCrypto shall call ODK_UpdateLastPlaybackTime. See the
 * document "License Duration and Renewal" for handling the return value of
 * these ODK functions.
 * The following checks should be performed if any subsamples contain any
 * encrypted bytes. If any check fails, an error is returned, and no
 * decryption is performed.
 *   1. If the current key's control block has the Data_Path_Type bit set,
 *      then the API shall verify that the output buffer is secure or direct.
 *      If not, return OEMCrypto_ERROR_DECRYPT_FAILED.
 *   2. If the current key control block has the bit Disable_Analog_Output
 *      set, then the device should disable analog video output.  If the
 *      device has analog video output that cannot be disabled, then
 *      OEMCrypto_ERROR_ANALOG_OUTPUT is returned.  (See note on delayed
 *      error conditions below)
 *   3. If the current key's control block has the HDCP bit set, then the API
 *      shall verify that the buffer will be displayed locally, or output
 *      externally using HDCP only.  If not, return
 *      OEMCrypto_ERROR_INSUFFICIENT_HDCP. (See note on delayed error
 *      conditions below)
 *   4. If the current key's control block has a nonzero value for
 *      HDCP_Version, then the current version of HDCP for the device and the
 *      display combined will be compared against the version specified in
 *      the control block.  If the current version is not at least as high as
 *      that in the control block, and the device is not able to restrict
 *      displays with HDCP levels lower than what's in the control block,
 *      return OEMCrypto_ERROR_INSUFFICIENT_HDCP. If the device is able to
 *      restrict those displays, return
 *      OEMCrypto_WARNING_MIXED_OUTPUT_PROTECTION.  (See note on delayed
 *      error conditions below)
 *   5. If the current session has an entry in the Usage Table, and the
 *      status of that entry is either kInactiveUsed or kInactiveUnused, then
 *      return the error OEMCrypto_ERROR_LICENSE_INACTIVE.
 *   6. If a Decrypt Hash has been initialized via OEMCrypto_SetDecryptHash,
 *      and the current key's control block does not have the
 *      Allow_Hash_Verification bit set, then do not compute a hash and
 *      return OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *
 * Delayed Error Conditions
 *
 * On some devices, the HDCP subsystem is not directly connected to the
 * OEMCrypto TA. This means that returning the error
 * OEMCrypto_ERROR_INSUFFICIENT_HDCP at the time of the decrypt call is a
 * performance hit. However, some devices have the ability to tag output
 * buffers with security requirements, such as the required HDCP level.
 * For those devices, when a call to OEMCrypto_DecryptCENC is made using a
 * key that requires HDCP output, and if the HDCP level on the output does
 * not meet the required level.
 *   - OEMCrypto may tag the output buffer as requiring HDCP at the required
 *      level and return OEMCrypto_SUCCESS.
 *   - Output shall not be sent to the display.
 *   - On the second or third call to OEMCrypto_DecryptCENC with the same
 *      key, OEMCrypto shall return OEMCrypto_ERROR_INSUFFICIENT_HDCP.
 * For those devices, when a call to OEMCrypto_DecryptCENC is made using a
 * key that requires HDCP output, and if the HDCP level on some of the
 * displays does not meet the required level.
 *   - OEMCrypto may tag the output buffer as requiring HDCP at the required
 *      level and return OEMCrypto_SUCCESS.
 *   - Output shall only be sent to the display with sufficient output
 *      control, e.g. the local display.
 *   - On the second or third call to OEMCrypto_DecryptCENC with the same
 *      key, OEMCrypto shall return OEMCrypto_WARNING_MIXED_OUTPUT_PROTECTION.
 * In either case, a call to OEMCrypto_GetHDCPCapability shall return the
 * current HDCP level.
 *
 * @param[in] session: Crypto session identifier. The crypto session in which
 *    decrypt is to be performed.
 * @param[in] samples: A caller-owned array of OEMCrypto_SampleDescription
 *    structures. Each entry in this array contains one sample of the content.
 * @param[in] samples_length: The length of the array pointed to by the samples
 *    parameter.
 * @param[in] pattern: A caller-owned structure indicating the encrypt/skip
 *    pattern as specified in the ISO-CENC standard.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_DECRYPT_FAILED
 * @retval OEMCrypto_ERROR_KEY_EXPIRED
 * @retval OEMCrypto_ERROR_INSUFFICIENT_HDCP
 * @retval OEMCrypto_ERROR_ANALOG_OUTPUT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_OUTPUT_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support subsample sizes and total input buffer sizes as
 *   specified by its resource rating tier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size. If OEMCrypto returns
 *   OEMCrypto_ERROR_BUFFER_TOO_LARGE, the CDM will break the buffer into
 *   smaller chunks. For high performance devices, OEMCrypto should handle
 *   larger buffers. We encourage OEMCrypto implementers not to artificially
 *   restrict the maximum buffer size.
 *   If OEMCrypto detects that the output data is too large, and breaking the
 *   buffer into smaller subsamples will not work, then it returns
 *   OEMCrypto_ERROR_OUTPUT_TOO_LARGE. This error will bubble up to the
 *   application, which can decide to skip the current frame of video or to
 *   switch to a lower resolution.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16. This method changed its name in API
 *   version 11.
 */
OEMCryptoResult OEMCrypto_DecryptCENC(
    OEMCrypto_SESSION session,
    const OEMCrypto_SampleDescription* samples,  // an array of samples.
    size_t samples_length,                       // the number of samples.
    const OEMCrypto_CENCEncryptPatternDesc* pattern);

/**
 * Copies the payload in the buffer referenced by the *data parameter into
 * the buffer referenced by the out_buffer parameter. The data is simply
 * copied. The definition of OEMCrypto_DestBufferDesc and subsample_flags are
 * the same as in OEMCrypto_DecryptCENC, above.
 *
 * The main difference between this and DecryptCENC is that this function may be
 * used before a license is loaded into a session. In particular, an application
 * will use this to copy the clear leader of a video to a secure buffer while
 * the license request is being generated, sent to the server, and the response
 * is being processed. This functionality is needed because an application may
 * not have read or write access to a secure destination buffer.
 *
 * NOTES:
 *
 * This method may be called several times before the data is used. The first
 * buffer in a chunk of data will have the OEMCrypto_FirstSubsample bit set
 * in subsample_flags. The last buffer in a chunk of data will have the
 * OEMCrypto_LastSubsample bit set in subsample_flags. The data will not be
 * used until after OEMCrypto_LastSubsample has been set. If an
 * implementation copies data immediately, it may ignore subsample_flags.
 *
 * If the destination buffer is secure, an offset may be specified.
 * CopyBuffer begins storing data out_buffer->secure.offset bytes after the
 * beginning of the secure buffer.
 *
 * @verification
 * The following checks should be performed.
 *  1. If either data or out_buffer is null, return
 *     OEMCrypto_ERROR_INVALID_CONTEXT.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] data_addr: An unaligned pointer to the buffer to be copied.
 * @param[in] data_addr_length: The length of the buffer, in bytes.
 * @param[in] out_buffer_descriptor: A caller-owned descriptor that specifies
 *    the handling of the byte stream. See OEMCrypto_DestbufferDesc for details.
 * @param[in] subsample_flags: bitwise flags indicating if this is the first,
 *    middle, or last subsample in a chunk of data. 1 = first subsample, 2 =
 *    last subsample, 3 = both first and last subsample, 0 = neither first nor
 *    last subsample.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_OUTPUT_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support subsample sizes and total input buffer sizes as
 *   specified by its resource rating tier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size. If OEMCrypto returns
 *   OEMCrypto_ERROR_BUFFER_TOO_LARGE, the calling function must break the
 *   buffer into smaller chunks. For high performance devices, OEMCrypto should
 *   handle larger buffers. We encourage OEMCrypto implementers not to
 *   artificially restrict the maximum buffer size.
 *   If OEMCrypto detects that the output data is too large, and breaking the
 *   buffer into smaller subsamples will not work, then it returns
 *   OEMCrypto_ERROR_OUTPUT_TOO_LARGE. This error will bubble up to the
 *   application, which can decide to skip the current frame of video or to
 *   switch to a lower resolution.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is changed in API version 15.
 */
OEMCryptoResult OEMCrypto_CopyBuffer(
    OEMCrypto_SESSION session, const OEMCrypto_SharedMemory* data_addr,
    size_t data_addr_length,
    const OEMCrypto_DestBufferDesc* out_buffer_descriptor,
    uint8_t subsample_flags);

/**
 * This function encrypts a generic buffer of data using the current key.
 *
 * If the session has an entry in the Usage Table, then OEMCrypto will update
 * the time_of_last_decrypt. If the status of the entry is "unused", then
 * change the status to "active" and set the time_of_first_decrypt.
 *
 * OEMCrypto shall be able to handle buffers at least 100 KiB long.
 *
 * @verification
 *   The following checks should be performed. If any check fails, an error is
 *   returned, and the data is not encrypted.
 *     1. The control bit for the current key shall have the Allow_Encrypt set.
 *        If not, return OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *     2. If this is the first use of a key for this session, then OEMCrypto
 *        shall call ODK_AttemptFirstPlayback to update the session's clock
 *        values and verify playback is allowed. If this is not the first use
 *        of a key for this session, then OEMCrypto shall call
 *        ODK_UpdateLastPlaybackTime. See the document "License Duration and
 *        Renewal" for handling the return value of these ODK functions.
 *     3. If the current session has an entry in the Usage Table, and the
 *        status of that entry is either kInactiveUsed or kInactiveUnused, then
 *        return the error OEMCrypto_ERROR_LICENSE_INACTIVE.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] in_buffer: pointer to memory containing data to be encrypted.
 * @param[in] in_buffer_length: length of the buffer, in bytes. The algorithm
 *    may restrict in_buffer_length to be a multiple of block size.
 * @param[in] iv: IV for encrypting data. Size is 128 bits.
 * @param[in] algorithm: Specifies which encryption algorithm to use.
 *    Currently, only CBC 128 mode is allowed for encryption.
 * @param[out] out_buffer: pointer to buffer in which encrypted data should be
 *    stored.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_KEY_EXPIRED
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 *
 * @buffer_size
 *   OEMCrypto shall support  buffers sizes of at least 100 KiB for generic
 *   crypto operations.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_Generic_Encrypt(
    OEMCrypto_SESSION session, const OEMCrypto_SharedMemory* in_buffer,
    size_t in_buffer_length, const uint8_t* iv, OEMCrypto_Algorithm algorithm,
    OEMCrypto_SharedMemory* out_buffer);

/**
 * This function decrypts a generic buffer of data using the current key.
 *
 * If the session has an entry in the Usage Table, then OEMCrypto will update
 * the time_of_last_decrypt. If the status of the entry is "unused", then
 * change the status to "active" and set the time_of_first_decrypt.
 *
 * OEMCrypto should be able to handle buffers at least 100 KiB long.
 *
 * @verification
 *   The following checks should be performed. If any check fails, an error is
 *   returned, and the data is not decrypted.
 *     1. The control bit for the current key shall have the Allow_Decrypt set.
 *        If not, return OEMCrypto_ERROR_DECRYPT_FAILED.
 *     2. If the current key's control block has the Data_Path_Type bit set,
 *        then return OEMCrypto_ERROR_DECRYPT_FAILED.
 *     3. If this is the first use of a key for this session, then OEMCrypto
 *        shall call ODK_AttemptFirstPlayback to update the session's clock
 *        values and verify playback is allowed. If this is not the first use
 *        of a key for this session, then OEMCrypto shall call
 *        ODK_UpdateLastPlaybackTime. See the document "License Duration and
 *        Renewal" for handling the return value of these ODK functions.
 *     4. If the current session has an entry in the Usage Table, and the
 *        status of that entry is either kInactiveUsed or kInactiveUnused, then
 *        return the error OEMCrypto_ERROR_LICENSE_INACTIVE.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] in_buffer: pointer to memory containing data to be encrypted.
 * @param[in] in_buffer_length: length of the buffer, in bytes. The algorithm
 *    may restrict in_buffer_length to be a multiple of block size.
 * @param[in] iv: IV for encrypting data. Size is 128 bits.
 * @param[in] algorithm: Specifies which encryption algorithm to use.
 *    Currently, only CBC 128 mode is allowed for decryption.
 * @param[out] out_buffer: pointer to buffer in which decrypted data should be
 *    stored.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_KEY_EXPIRED
 * @retval OEMCrypto_ERROR_DECRYPT_FAILED
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 *
 * @buffer_size
 *   OEMCrypto shall support  buffers sizes of at least 100 KiB for generic
 *   crypto operations.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_Generic_Decrypt(
    OEMCrypto_SESSION session, const OEMCrypto_SharedMemory* in_buffer,
    size_t in_buffer_length, const uint8_t* iv, OEMCrypto_Algorithm algorithm,
    OEMCrypto_SharedMemory* out_buffer);

/**
 * This function signs a generic buffer of data using the current key.
 *
 * If the session has an entry in the Usage Table, then OEMCrypto will update
 * the time_of_last_decrypt. If the status of the entry is "unused", then
 * change the status to "active" and set the time_of_first_decrypt.
 *
 * @verification
 *   The following checks should be performed. If any check fails, an error is
 *   returned, and the data is not signed.
 *     1. The control bit for the current key shall have the Allow_Sign set.
 *     2. If this is the first use of a key for this session, then OEMCrypto
 *        shall call ODK_AttemptFirstPlayback to update the session's clock
 *        values and verify playback is allowed. If this is not the first use
 *        of a key for this session, then OEMCrypto shall call
 *        ODK_UpdateLastPlaybackTime. See the document "License Duration and
 *        Renewal" for handling the return value of these ODK functions.
 *     3. If the current session has an entry in the Usage Table, and the
 *        status of that entry is either kInactiveUsed or kInactiveUnused, then
 *        return the error OEMCrypto_ERROR_LICENSE_INACTIVE.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] buffer: pointer to memory containing data to be encrypted.
 * @param[in] buffer_length: length of the buffer, in bytes.
 * @param[in] algorithm: Specifies which algorithm to use.
 * @param[out] signature: pointer to buffer in which signature should be
 *    stored. May be null on the first call in order to find required buffer
 *    size.
 * @param[in,out] signature_length: (in) length of the signature buffer, in
 *    bytes. (out) actual length of the signature
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_KEY_EXPIRED
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if signature buffer is not large enough
 *         to hold the output signature.
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 *
 * @buffer_size
 *   OEMCrypto shall support  buffers sizes of at least 100 KiB for generic
 *   crypto operations.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_Generic_Sign(OEMCrypto_SESSION session,
                                       const OEMCrypto_SharedMemory* buffer,
                                       size_t buffer_length,
                                       OEMCrypto_Algorithm algorithm,
                                       OEMCrypto_SharedMemory* signature,
                                       size_t* signature_length);

/**
 * This function verifies the signature of a generic buffer of data using the
 * current key.
 *
 * If the session has an entry in the Usage Table, then OEMCrypto will update
 * the time_of_last_decrypt. If the status of the entry is "unused", then
 * change the status to "active" and set the time_of_first_decrypt.
 *
 * @verification
 *   The following checks should be performed. If any check fails, an error is
 *   returned.
 *     1. The control bit for the current key shall have the Allow_Verify set.
 *     2. The signature of the message shall be computed, and the API shall
 *        verify the computed signature matches the signature passed in.  If
 *        not, return OEMCrypto_ERROR_SIGNATURE_FAILURE.
 *     3. The signature verification shall use a constant-time algorithm (a
 *        signature mismatch will always take the same time as a successful
 *        comparison).
 *     4. If this is the first use of a key for this session, then OEMCrypto
 *        shall call ODK_AttemptFirstPlayback to update the session's clock
 *        values and verify playback is allowed. If this is not the first use
 *        of a key for this session, then OEMCrypto shall call
 *        ODK_UpdateLastPlaybackTime. See the document "License Duration and
 *        Renewal" for handling the return value of these ODK functions.
 *     5. If the current session has an entry in the Usage Table, and the
 *        status of that entry is either kInactiveUsed or kInactiveUnused, then
 *        return the error OEMCrypto_ERROR_LICENSE_INACTIVE.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] buffer: pointer to memory containing data to be encrypted.
 * @param[in] buffer_length: length of the buffer, in bytes.
 * @param[in] algorithm: Specifies which algorithm to use.
 * @param[in] signature: pointer to buffer in which signature resides.
 * @param[in] signature_length: length of the signature buffer, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_KEY_EXPIRED
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 *
 * @buffer_size
 *   OEMCrypto shall support  buffers sizes of at least 100 KiB for generic
 *   crypto operations.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_Generic_Verify(
    OEMCrypto_SESSION session, const OEMCrypto_SharedMemory* buffer,
    size_t buffer_length, OEMCrypto_Algorithm algorithm,
    const OEMCrypto_SharedMemory* signature, size_t signature_length);

/// @}

/// @addtogroup factory_provision
/// @{

/**
 * A device should be provisioned at the factory with either an OEM
 * Certificate or a keybox. We will call this data the root of trust. During
 * manufacturing, the root of trust should be encrypted with the OEM root key
 * and stored on the file system in a region that will not be erased during
 * factory reset. This function may be used by legacy systems that use the
 * two-step WrapKeyboxOrOEMCert/InstallKeyboxOrOEMCert approach. When the
 * Widevine DRM plugin initializes, it will look for a wrapped root of trust
 * in the file /factory/wv.keys and install it into the security processor by
 * calling OEMCrypto_InstallKeyboxOrOEMCert().
 *
 * Figure 10. OEMCrypto_WrapKeyboxOrOEMCert Operation
 *
 * OEMCrypto_WrapKeyboxOrOEMCert() is used to generate an OEM-encrypted root
 * of trust that may be passed to OEMCrypto_InstallKeyboxOrOEMCert() for
 * provisioning. The root of trust may be either passed in the clear or
 * previously encrypted with a transport key. If a transport key is supplied,
 * the keybox is first decrypted with the transport key before being wrapped
 * with the OEM root key. This function is only needed if the root of trust
 * provisioning method involves saving the keybox or OEM Certificate to the
 * file system.
 *
 * @param[in] keybox_or_cert: pointer to root of trust data to encrypt -- this
 *    is either a keybox or an OEM Certificate private key. May be NULL on the
 *    first call to test the size of the wrapped keybox. The keybox may either
 *    be clear or previously encrypted.
 * @param[in] keybox_or_cert_length: length the keybox or cert data in bytes
 * @param[out] wrapped_keybox_or_cert: Pointer to wrapped keybox or cert
 * @param[in,out] wrapped_keybox_or_cert_length: Pointer to the length of the
 *    wrapped keybox or certificate key in bytes
 * @param[in] transport_key: Optional. AES transport key. If provided, the
 *    keybox_or_cert parameter was previously encrypted with this key. The
 *    keybox will be decrypted with the transport key using AES-CBC and a null
 *    IV.
 * @param[in] transport_key_length: Optional. Number of bytes in the
 *    transport_key, if used.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_WRITE_KEYBOX failed to encrypt the keybox
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if keybox is provided as NULL, to
 *         determine the size of the wrapped keybox
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system.
 *
 * @version
 *   This method is supported in all API versions.
 */
OEMCryptoResult OEMCrypto_WrapKeyboxOrOEMCert(
    const uint8_t* keybox_or_cert, size_t keybox_or_cert_length,
    uint8_t* wrapped_keybox_or_cert, size_t* wrapped_keybox_or_cert_length,
    const uint8_t* transport_key, size_t transport_key_length);

/**
 * Decrypts a wrapped root of trust and installs it in the security
 * processor. The root of trust is unwrapped then encrypted with the OEM root
 * key. This function is called from the Widevine DRM plugin at
 * initialization time if there is no valid root of trust installed. It looks
 * for wrapped data in the file /factory/wv.keys and if it is present, will
 * read the file and call OEMCrypto_InstallKeyboxOrOEMCert() with the
 * contents of the file. This function is only needed if the factory
 * provisioning method involves saving the keybox or OEM Certificate to the
 * file system.
 *
 * @param[in] keybox_or_cert: pointer to encrypted data as input
 * @param[in] keybox_or_cert_length: length of the data in bytes
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_BAD_MAGIC
 * @retval OEMCrypto_ERROR_BAD_CRC
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system.
 *
 * @version
 *   This method is supported in all API versions.
 */
OEMCryptoResult OEMCrypto_InstallKeyboxOrOEMCert(const uint8_t* keybox_or_cert,
                                                 size_t keybox_or_cert_length);

/**
 * This function is for OEMCrypto to tell the layer above what provisioning
 * method it uses: keybox or OEM certificate.
 *
 * @retval OEMCrypto_DrmCertificate means the device has a DRM certificate built
 *         into the system.  This cannot be used by level 1 devices.  This
 *         provisioning method is deprecated and should not be used on new
 *         devices.  OEMCertificate provisioning should be used instead.
 * @retval OEMCrypto_Keybox means the device has a unique keybox.  For level 1
 *         devices this keybox must be securely installed by the device
 *         manufacturer.
 * @retval OEMCrypto_OEMCertificate means the device has a factory installed OEM
 *         certificate.  This is also called Provisioning 3.0.
 * @retval OEMCrypto_ProvisioningError indicates a serious problem with the
 *         OEMCrypto library.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new API version 12.
 */
OEMCrypto_ProvisioningMethod OEMCrypto_GetProvisioningMethod(void);

/**
 * If the device has a keybox, this validates the Widevine Keybox loaded into
 * the security processor device. This method verifies two fields in the
 * keybox:
 *
 *   - Verify the MAGIC field contains a valid signature (such as,
 *      'k''b''o''x').
 *   - Compute the CRC using CRC-32-POSIX-1003.2 standard and compare the
 *      checksum to the CRC stored in the Keybox.
 * The CRC is computed over the entire Keybox excluding the 4 bytes of the
 * CRC (for example, Keybox[0..123]). For a description of the fields stored
 * in the keybox, see Keybox Definition.
 *
 * If the device has an OEM Certificate, this validates the certificate
 * private key.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_BAD_MAGIC
 * @retval OEMCrypto_ERROR_BAD_CRC
 * @retval OEMCrypto_ERROR_KEYBOX_INVALID
 * @retval OEMCrypto_ERROR_INVALID_RSA_KEY
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is supported in all API versions.
 */
OEMCryptoResult OEMCrypto_IsKeyboxOrOEMCertValid(void);

/**
 * Return a device unique id. For devices with a keybox, retrieve the
 * DeviceID from the Keybox. For devices that have an OEM Certificate instead
 * of a keybox, it should set the device ID to a device-unique string, such
 * as the device serial number. The ID should be device-unique and it should
 * be stable -- i.e. it should not change across a device reboot or a system
 * upgrade. This shall match the device id found in the core provisioning
 * request message. The maximum length of the device id is 64 bytes. The
 * device ID field in a keybox is 32 bytes.
 *
 * @param[out] device_id: pointer to the buffer that receives the Device ID.
 * @param[in,out] device_id_length - on input, size of the caller's device ID
 *    buffer. On output, the number of bytes written into the buffer.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if the buffer is too small to return
 *         device ID
 * @retval OEMCrypto_ERROR_NO_DEVICEID failed to return Device Id
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is supported in all API versions.
 */
OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* device_id,
                                      size_t* device_id_length);

/// @}

/// @addtogroup keybox
/// @{

/**
 * Return the Key Data field from the Keybox.
 *
 * @param[out] key_data: pointer to the buffer to hold the Key Data field from
 *    the Keybox
 * @param[in,out] key_data_length: on input, the allocated buffer size. On
 *    output, the number of bytes in Key Data
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if the buffer is too small to return
 *         KeyData
 * @retval OEMCrypto_ERROR_NO_KEYDATA
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED: this function is for
 *         Provisioning 2.0 only.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is supported in all API versions.
 */
OEMCryptoResult OEMCrypto_GetKeyData(uint8_t* key_data,
                                     size_t* key_data_length);

/**
 * Temporarily use the specified test keybox until the next call to
 * OEMCrypto_Terminate. This allows a standard suite of unit tests to be run
 * on a production device without permanently changing the keybox. Using the
 * test keybox is not persistent. OEMCrypto cannot assume that this keybox is
 * the same as previous keyboxes used for testing.
 *
 * Devices that use an OEM Certificate instead of a keybox (i.e. Provisioning
 * 3.0) do not need to support this functionality, and may return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED.
 *
 * @param[in] buffer: pointer to memory containing test keybox, in binary form.
 * @param[in] buffer_length: length of the buffer, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED this function is for
 *         Provisioning 2.0 only.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system. It is called after OEMCrypto_Initialize and
 *   after OEMCrypto_GetProvisioningMethod and only if the provisoining method
 *   is OEMCrypto_Keybox,
 *
 * @version
 *   This method changed in API version 14.
 */
OEMCryptoResult OEMCrypto_LoadTestKeybox(const uint8_t* buffer,
                                         size_t buffer_length);

/// @}

/// @addtogroup oem_cert
/// @{
/**
 * After a call to this function, all session functions using an RSA key
 * should use the OEM certificate's private RSA key. See the section above
 * discussing Provisioning 3.0.
 *
 * @param[in] session: this function affects the specified session only.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED this function is for
 *         Provisioning 3.0 only.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new API version 16.
 */
OEMCryptoResult OEMCrypto_LoadOEMPrivateKey(OEMCrypto_SESSION session);

/**
 * This function should place the OEM public certificate in the buffer
 * public_cert. See the section above discussing Provisioning 3.0.
 *
 * If the buffer is not large enough, OEMCrypto should update
 * public_cert_length and return OEMCrypto_ERROR_SHORT_BUFFER.
 *
 * @param[out] public_cert: the buffer where the public certificate is stored.
 * @param[in,out] public_cert_length: on input, this is the available size of
 *    the buffer.  On output, this is the number of bytes needed for the
 *    certificate.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED this function is for
 *         Provisioning 3.0 only.
 * @retval OEMCrypto_ERROR_SHORT_BUFFER
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new API version 16.
 */
OEMCryptoResult OEMCrypto_GetOEMPublicCertificate(uint8_t* public_cert,
                                                  size_t* public_cert_length);

/// @}

/// @addtogroup validation
/// @{

/**
 * Returns a buffer filled with hardware-generated random bytes, if supported
 * by the hardware. If the hardware feature does not exist, return
 * OEMCrypto_ERROR_RNG_NOT_SUPPORTED.
 *
 * @param[out] random_data: pointer to the buffer that receives random data
 * @param[in] random_data_length: length of the random data buffer in bytes
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_RNG_FAILED failed to generate random number
 * @retval OEMCrypto_ERROR_RNG_NOT_SUPPORTED function not supported
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support random_data_length sizes of at least 32 bytes
 *   for random number generation.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is supported in all API versions.
 */
OEMCryptoResult OEMCrypto_GetRandom(uint8_t* random_data,
                                    size_t random_data_length);

/**
 * This function returns the current API version number. The version number
 * allows the calling application to avoid version mis-match errors, because
 * this API is part of a shared library.
 *
 * There is a possibility that some API methods will be backwards compatible,
 * or backwards compatible at a reduced security level.
 *
 * There is no plan to introduce forward-compatibility. Applications will
 * reject a library with a newer version of the API.
 *
 * The version specified in this document is 16. Any OEM that returns this
 * version number guarantees it passes all unit tests associated with this
 * version.
 *
 * @retval The supported API, as specified in the header file OEMCryptoCENC.h.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in each API version.
 */
uint32_t OEMCrypto_APIVersion(void);

/**
 * This function returns the current API minor version number. The version
 * number allows the calling application to avoid version mis-match errors,
 * because this API is part of a shared library.
 *
 * The minor version specified in this document is 2. Any OEM that returns
 * this version number guarantees it passes all unit tests associated with
 * this version.
 *
 * @retval The supported API, as specified in the header file OEMCryptoCENC.h.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in each API version.
 */
uint32_t OEMCrypto_MinorAPIVersion(void);

/**
 * Report the build information of the OEMCrypto library as a short null
 * terminated C string. The string should be at most 128 characters long.
 * This string should be updated with each release or OEMCrypto build.
 *
 * Some SOC vendors deliver a binary OEMCrypto library to a device
 * manufacturer. This means the OEMCrypto version may not be exactly in sync
 * with the system's versions. This string can be used to help track which
 * version is installed on a device.
 *
 * It may be used for logging or bug tracking and may be bubbled up to the
 * app so that it may track metrics on errors.
 *
 * Since the OEMCrypto API also changes its minor version number when there
 * are minor corrections, it would be useful to include the API version
 * number in this string, e.g. "15.1" or "15.2" if those minor versions are
 * released.
 *
 * @retval A printable null terminated C string, suitable for a single line in a
 *         log.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in each API version.
 */
const char* OEMCrypto_BuildInformation(void);

/**
 * This function returns the current patch level of the software running in
 * the trusted environment. The patch level is defined by the OEM, and is
 * only incremented when a security update has been added.
 *
 * See the section Security Patch Level above for more details.
 *
 * @retval The OEM defined version number.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method was introduced in API version 11.
 */
uint8_t OEMCrypto_Security_Patch_Level(void);

/**
 * Returns a string specifying the security level of the library.
 *
 * Since this function is spoofable, it is not relied on for security
 * purposes. It is for information only.
 *
 * @retval A null terminated string. Useful value are "L1", "L2" and "L3".
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 6.
 */
const char* OEMCrypto_SecurityLevel(void);

/**
 * Returns the maximum HDCP version supported by the device, and the HDCP
 * version supported by the device and any connected display.
 *
 * Valid values for HDCP_Capability are:
 *
 * The value 0xFF means the device is using a local, secure, data path
 * instead of HDMI output. Notice that HDCP must use flag Type 1: all
 * downstream devices will also use the same version or higher.
 *
 * The maximum HDCP level should be the maximum value that the device can
 * enforce. For example, if the device has an HDCP 1.0 port and an HDCP 2.0
 * port, and the first port can be disabled, then the maximum is HDCP 2.0. If
 * the first port cannot be disabled, then the maximum is HDCP 1.0. The
 * maximum value can be used by the application or server to decide if a
 * license may be used in the future. For example, a device may be connected
 * to an external display while an offline license is downloaded, but the
 * user intends to view the content on a local display. The user will want to
 * download the higher quality content.
 *
 * The current HDCP level should be the level of HDCP currently negotiated
 * with any connected receivers or repeaters either through HDMI or a
 * supported wireless format. If multiple ports are connected, the current
 * level should be the minimum HDCP level of all ports. If the key control
 * block requires an HDCP level equal to or lower than the current HDCP
 * level, the key is expected to be usable. If the key control block requires
 * a higher HDCP level, the key is expected to be forbidden.
 *
 * When a key has version HDCP_V2_3 required in the key control block, the
 * transmitter must have HDCP version 2.3 and have negotiated a connection
 * with a version 2.2 or 2.3 receiver or repeater. The transmitter must
 * configure the content stream to be Type 1. Since the transmitter cannot
 * distinguish between 2.2 and 2.3 downstream receivers when connected to a
 * repeater, it may transmit to both 2.2 and 2.3 receivers, but not 2.1
 * receivers.
 *
 * For example, if the transmitter is 2.3, and is connected to a receiver
 * that supports 2.3 then the current level is HDCP_V2_3. If the transmitter
 * is 2.3 and is connected to a 2.3 repeater, the current level is HDCP_V2_3
 * even though  the repeater can negotiate a connection with a 2.2 downstream
 * receiver for a Type 1 Content Stream.
 *
 * As another example, if the transmitter can support 2.3, but a receiver
 * supports 2.0, then the current level is HDCP_V2.
 *
 * When a license requires HDCP, a device may use a wireless protocol to
 * connect to a display only if that protocol supports the version of HDCP as
 * required by the license. Both WirelessHD (formerly WiFi Display) and
 * Miracast support HDCP.
 *
 * @param[out] current: this is the current HDCP version, based on the device
 *    itself, and the display to which it is connected.
 * @param[out] maximum: this is the maximum supported HDCP version for the
 *    device, ignoring any attached device.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 10.
 */
OEMCryptoResult OEMCrypto_GetHDCPCapability(OEMCrypto_HDCP_Capability* current,
                                            OEMCrypto_HDCP_Capability* maximum);

/**
 * This is used to determine if the device can support a usage table. Since
 * this function is spoofable, it is not relied on for security purposes. It
 * is for information only. The usage table is described in the section above.
 *
 * @retval Returns true if the device can maintain a usage table. Returns false
 *         otherwise.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 9.
 */
bool OEMCrypto_SupportsUsageTable(void);

/**
 * Estimates the maximum usage table size. If the device does not have a
 * fixed size, this returns an estimate. A maximum size of 0 means the header
 * is constrained only by dynamic memory allocation.
 *
 * Widevine requires the size to be at least 300 entries.
 *
 * @retval Returns an estimate for the maximum size of the usage table header.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 16.
 */
size_t OEMCrypto_MaximumUsageTableHeaderSize(void);

/**
 * Indicate whether there is hardware protection to detect and/or prevent the
 * rollback of the usage table. For example, if the usage table contents is
 * stored entirely on a secure file system that the user cannot read or write
 * to. Another example is if the usage table has a generation number and the
 * generation number is stored in secure memory that is not user accessible.
 *
 * @retval Returns true if oemcrypto uses anti-rollback hardware. Returns false
 *         otherwise.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 10.
 */
bool OEMCrypto_IsAntiRollbackHwPresent(void);

/**
 * Returns the current number of open sessions. The CDM and OEMCrypto
 * consumers can query this value so they can use resources more effectively.
 *
 * @param[out] count: this is the current number of opened sessions.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 10.
 */
OEMCryptoResult OEMCrypto_GetNumberOfOpenSessions(size_t* count);

/**
 * Returns the maximum number of concurrent OEMCrypto sessions supported by
 * the device. The CDM and OEMCrypto consumers can query this value so they
 * can use resources more effectively. If the maximum number of sessions
 * depends on a dynamically allocated shared resource, the returned value
 * should be a best estimate of the maximum number of sessions.
 *
 * OEMCrypto shall support a minimum of 10 sessions. Some applications use
 * multiple sessions to pre-fetch licenses, so high end devices should
 * support more sessions -- we recommend a minimum of 50 sessions.
 *
 * @param[out] max: this is the max number of supported sessions.
 *
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 12.
 */
OEMCryptoResult OEMCrypto_GetMaxNumberOfSessions(size_t* max);

/**
 * Returns the type of certificates keys that this device supports. With very
 * few exceptions, all devices should support at least 2048 bit RSA keys.
 * High end devices should also support 3072 bit RSA keys. Devices that are
 * cast receivers should also support RSA cast receiver certificates.
 *
 * Beginning with OEMCrypto v14, the provisioning server may deliver to the
 * device an RSA key that uses the Carmichael totient. This does not change
 * the RSA algorithm -- however the product of the private and public keys is
 * not necessarily the Euler number  \phi (n). OEMCrypto should not reject
 * such keys.
 *
 * @return
 *   Returns the bitwise or of the following flags. It is likely that high end
 *         devices will support both 2048 and 3072 bit keys while the widevine
 *         servers transition to new key sizes.
 *     - 0x1 = OEMCrypto_Supports_RSA_2048bit - the device can load a DRM
 *        certificate with a 2048 bit RSA key.
 *     - 0x2 = OEMCrypto_Supports_RSA_3072bit - the device can load a DRM
 *        certificate with a 3072 bit RSA key.
 *     - 0x10 = OEMCrypto_Supports_RSA_CAST - the device can load a CAST
 *        certificate.  These certificates are used with
 *        OEMCrypto_GenerateRSASignature with padding type set to 0x2, PKCS1
 *        with block type 1 padding.
 *     - 0x100 = OEMCrypto_Supports_ECC_secp256r1 - Elliptic Curve secp256r1
 *     - 0x200 = OEMCrypto_Supports_ECC_secp384r1 - Elliptic Curve secp384r1
 *     - 0x400 = OEMCrypto_Supports_ECC_secp521r1 - Elliptic Curve secp521r1
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 16.
 */
uint32_t OEMCrypto_SupportedCertificates(void);

/**
 * Returns true if the device supports SRM files and the file can be updated
 * via the function OEMCrypto_LoadSRM. This also returns false for devices
 * that do not support an SRM file, devices that do not support HDCP, and
 * devices that have no external display support.
 *
 * @retval true if LoadSRM is supported.
 * @retval false otherwise.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 13.
 */
bool OEMCrypto_IsSRMUpdateSupported(void);

/**
 * Returns the version number of the current SRM file. If the device does not
 * support SRM files, this will return OEMCrypto_ERROR_NOT_IMPLEMENTED. If
 * the device only supports local displays, it would return
 * OEMCrypto_LOCAL_DISPLAY_ONLY. If the device has an SRM, but cannot use
 * OEMCrypto to update the SRM, then this function would set version to be
 * the current version number, and return OEMCrypto_SUCCESS, but it would
 * return false from OEMCrypto_IsSRMUpdateSupported.
 *
 * @param[out] version: current SRM version number.
 *
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_SUCCESS
 * @retval OEMCrypto_LOCAL_DISPLAY_ONLY to indicate version was not set, and
 *         is not needed.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_GetCurrentSRMVersion(uint16_t* version);

/**
 * Returns whether the device supports analog output or not. This information
 * will be sent to the license server, and may be used to determine the type
 * of license allowed. This function is for reporting only. It is paired with
 * the key control block flags Disable_Analog_Output and CGMS.
 *
 * @return
 *   Returns a bitwise OR of all possible return values.
 *   * 0x0 = OEMCrypto_No_Analog_Output: the device has no analog output.
 *   * 0x1 = OEMCrypto_Supports_Analog_Output: the device does have analog
 *        output.
 *   * 0x2 = OEMCrypto_Can_Disable_Analog_Ouptput: the device does have
 *        analog output, but it will disable analog output if required by the
 *        key control block.
 *   * 0x4 = OEMCrypto_Supports_CGMS_A: the device supports signaling 2-bit
 *        CGMS-A, if required by the key control block
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 14.
 */
uint32_t OEMCrypto_GetAnalogOutputFlags(void);

/**
 * This function returns a positive number indicating which resource rating
 * it supports. This value will bubble up to the application level as a
 * property. This will allow applications to estimate what resolution and
 * bandwidth the device is expected to support.
 *
 * OEMCrypto unit tests and Android GTS tests will verify that devices do
 * support the resource values specified in the table below at the tier
 * claimed by the device. If a device claims to be a low end device, the
 * OEMCrypto unit tests will only verify the low end performance values.
 *
 * OEMCrypto implementers should consider the numbers below to be minimum
 * values.
 *
 * These performance parameters are for OEMCrypto only. In particular,
 * bandwidth and codec resolution are determined by the platform.
 *
 * Some parameters need more explanation. The Sample size is typically the
 * size of one encoded frame, but might be several frames for AV1. Converting
 * this to resolution depends on the Codec, which is not specified by
 * OEMCrypto. Some content has the sample broken into several subsamples. The
 * "number of subsamples" restriction requires that any content can be broken
 * into at least that many subsamples. However, this number may be larger if
 * DecryptCENC returns OEMCrypto_ERROR_BUFFER_TOO_LARGE. In that case, the
 * layer above OEMCrypto will break the sample into subsamples of size
 * "Decrypt Buffer Size" as specified in the table below. The "Decrypt Buffer
 * Size" means the size of one subsample that may be passed into DecryptCENC
 * or CopyBuffer without returning error OEMCrypto_ERROR_BUFFER_TOO_LARGE.
 *
 * The minimum subsample buffer size is the smallest buffer that the CDM
 * layer above OEMCrypto will use when breaking a sample into subsamples. As
 * mentioned above, the CDM layer will only break a sample into smaller
 * subsamples if OEMCrypto returns OEMCrypto_ERROR_BUFFER_TOO_LARGE. Because
 * this might be a performance problem, OEMCrypto implementers are encouraged
 * to process larger subsamples and to process multiple subsamples in a
 * single call to DecryptCENC.
 *
 * The number of keys per session is an indication of how many different
 * track types there can be for a piece of content. Typically, content will
 * have several keys corresponding to audio and video at different
 * resolutions. If the content uses key rotation, there could be three keys
 * -- previous interval, current interval, and next interval -- for each
 * resolution.
 *
 * Concurrent playback sessions versus concurrent sessions: some applications
 * will preload multiple licenses before the user picks which content to
 * play. Each of these licenses corresponds to an open session. Once playback
 * starts, some platforms support picture-in-picture or multiple displays.
 * Each of these pictures would correspond to a separate playback session
 * with active decryption.
 *
 * The total number of keys for all sessions indicates that the device may
 * share key memory over multiple sessions. For example, on a Tier 3 device,
 * the device must support four sessions with 20 keys each (80 total), or 20
 * sessions with 4 keys each (80 total), but it does not need to support 20
 * sessions with 20 keys each.
 *
 * The message size that is needed for a license with a large number of keys
 * is larger than in previous versions. The message size limit applies to all
 * functions that sign or verify messages. It also applies to the size of
 * context buffers in the derive key functions.
 *
 * Decrypted frames per second -- strictly speaking, OEMCrypto only controls
 * the decryption part of playback and cannot control the decoding and
 * display part. However, devices that support the higher resource tiers
 * should also support a higher frame rate. Platforms may enforce these
 * values. For example Android will enforce a frame rate via a GTS test.
 *
 * Note on units: We will use KiB to mean 1024 bytes and MiB to mean 1024
 * KiB, as described at https://en.wikipedia.org/wiki/Kibibyte.
 *
 * <pre>
 * +--------------------------------+---------+----------+---------+---------+
 * |Resource Rating Tier            |1 - Low  |2 - Medium|3 - High |4 - Very |
 * |                                |         |          |         |    High |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum Sample size             |1 MiB    |2 MiB     |4 MiB    |16 MiB   |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum Number of Subsamples    |10       |16        |32       |64       |
 * | (H264 or HEVC)                 |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum Number of Subsamples    |9        |9         |9        |9        |
 * |(VP9)                           |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum Number of Subsamples    |72       |144       |288      |576      |
 * |(AV1)                           |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum subsample buffer size   |100 KiB  |500 KiB   |1 MiB    |4 MiB    |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum Generic crypto buffer   |10 KiB   |100 KiB   |500 KiB  |1 MiB    |
 * |size                            |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum number of concurrent    |10       |20        |30       |40       |
 * |sessions                        |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum number of keys per      |4        |20        |20       |30       |
 * |session                         |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum total number of keys    |16       |40        |80       |90       |
 * | (all sessions)                 |         |          |         |         |
 * +--------------------------------+---------+----------+---------+---------+
 * |Minimum Message Size            |8 KiB    |8 KiB     |16 KiB   |32 KiB   |
 * +--------------------------------+---------+----------+---------+---------+
 * |Decrypted Frames per Second     |30 fps SD|30 fps HD |60 fps HD|60 fps 8k|
 * +--------------------------------+---------+----------+---------+---------+
 * </pre>
 *
 * @return
 * Returns an integer indicating which resource tier the device supports.
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 15.
 */
uint32_t OEMCrypto_ResourceRatingTier(void);

/// @}

/// @addtogroup drm_cert
/// @{

/**
 * Load and parse a provisioning response, and then rewrap the private key
 * for storage on the filesystem. We recommend that the OEM use an encryption
 * key and signing key generated using an algorithm at least as strong as
 * that in GenerateDerivedKeys.
 *
 * First, OEMCrypto shall verify the signature of the message using
 * HMAC-SHA256 with the derived mac_key[server]. The signature verification
 * shall use a constant-time algorithm (a signature mismatch will always take
 * the same time as a successful comparison). The signature is over the
 * entire message buffer starting at message with length message_length. If
 * the signature verification fails, ignore all other arguments and return
 * OEMCrypto_ERROR_SIGNATURE_FAILURE.
 *
 * NOTE: The calling software must have previously established the mac_keys
 * and encrypt_key with a call to OEMCrypto_DeriveKeysFromSessionKey or
 * OEMCrypto_GenerateDerivedKeys.
 *
 * The function ODK_ParseProvisioning is called to parse the message. If it
 * returns an error, OEMCrypto shall return that error to the CDM layer. The
 * function ODK_ParseProvisioning is described in the document "Widevine Core
 * Message Serialization".
 *
 * Below, all fields are found in the struct ODK_ParsedLicense parsed_license
 * returned by ODK_ParsedProvisioning.
 *
 * After decrypting `parsed_response->enc_private_key`, If the first four bytes
 * of the buffer are the string "SIGN", then the actual RSA key begins on the
 * 9th byte of the buffer. The second four bytes of the buffer is the 32 bit
 * field "allowed_schemes" of type RSA_Padding_Scheme, which is used in
 * OEMCrypto_GenerateRSASignature. The value of allowed_schemes must also be
 * wrapped with RSA key. We recommend storing the magic string "SIGN" with
 * the key to distinguish keys that have a value for allowed_schemes from
 * those that should use the default allowed_schemes. Devices that do not
 * support the alternative signing algorithms may refuse to load these keys
 * and return an error of OEMCrypto_ERROR_NOT_IMPLEMENTED. The main use case
 * for these alternative signing algorithms is to support devices that use
 * X509 certificates for authentication when acting as a ChromeCast receiver.
 * This is not needed for devices that wish to send data to a ChromeCast.
 *
 * If the first four bytes of the buffer `enc_private_key` are not the string
 * "SIGN", then this key may not be used with OEMCrypto_GenerateRSASignature.
 *
 * Verification and Algorithm:
 * The following checks should be performed. If any check fails, an error is
 * returned, and the key is not loaded.
 *   1. Check that all the pointer values passed into it are within the
 *      buffer specified by message and message_length.
 *   2. Verify that (in) wrapped_private_key_length is large enough to hold
 *      the rewrapped key, returning OEMCrypto_ERROR_SHORT_BUFFER otherwise.
 *   3. Verify the message signature, using the derived signing key
 *      (mac_key[server]) from a previous call to
 *      OEMCrypto_GenerateDerivedKeys or OEMCrypto_DeriveKeysFromSessionKey.
 *   4. The function ODK_ParseProvisioning is called to parse the message.
 *   5. Decrypt enc_private_key in the buffer private_key using the session's
 *      derived encryption key (enc_key).  Use enc_private_key_iv as the initial
 *      vector for AES_128-CBC mode, with PKCS#5 padding. The private_key should
 *      be kept in secure memory and protected from the user.
 *   6. If the first four bytes of the buffer private_key are the string "SIGN",
 *      then the  actual RSA key begins on the 9th byte of the buffer.  The
 *      second four bytes of the buffer is the 32 bit field
 *      "allowed_schemes", of type RSA_Padding_Scheme, which is used in
 *      OEMCrypto_GenerateRSASignature.    The value of allowed_schemes must
 *      also be wrapped with RSA key. We recommend storing the magic string
 *      "SIGN" with the key to distinguish keys that have a value for
 *      allowed_schemes from those that should use the default
 *      allowed_schemes. Devices that do not support the alternative signing
 *      algorithms may refuse to load these keys and return an error of
 *      OEMCrypto_ERROR_NOT_IMPLEMENTED.  The main use case for these
 *      alternative signing algorithms is to support devices that use X.509
 *      certificates for authentication when acting as a ChromeCast receiver.
 *      This is not needed for devices that wish to send data to a ChromeCast.
 *   7. If the first four bytes of the buffer private_key are not the string
 *      "SIGN", this key may not be used with OEMCrypto_GenerateRSASignature.
 *   8. After possibly skipping past the first 8 bytes signifying the allowed
 *      signing algorithm, the rest of the buffer private_key contains an ECC
 *      private key or an RSA private key in PKCS#8 binary DER encoded
 *      format. The OEMCrypto library shall verify that this private key is
 *      valid.
 *   9. Re-encrypt the device private key with an internal key (such as the OEM
 *      key or Widevine Keybox key) and the generated IV using AES-128-CBC
 *      with PKCS#5 padding.
 *   10. Copy the rewrapped key to the buffer specified by wrapped_private_key
 *      and the size of the wrapped key to wrapped_private_key_length.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] message: pointer to memory containing data.
 * @param[in] message_length: length of the message, in bytes.
 * @param[in] core_message_length: length of the core submessage, in bytes.
 * @param[in] signature: pointer to memory containing the signature.
 * @param[in] signature_length: length of the signature, in bytes.
 * @param[out] wrapped_private_key: pointer to buffer in which encrypted RSA or
 *    ECC private key should be stored. May be null on the first call in order
 *    to find required buffer size.
 * @param[in,out] wrapped_private_key_length: (in) length of the encrypted
 *    private key, in bytes. (out) actual length of the encrypted private key
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_RSA_KEY
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE
 * @retval OEMCrypto_ERROR_INVALID_NONCE
 * @retval OEMCrypto_ERROR_SHORT_BUFFER
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_LoadProvisioning(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    size_t core_message_length, const uint8_t* signature,
    size_t signature_length, uint8_t* wrapped_private_key,
    size_t* wrapped_private_key_length);

/**
 * Loads a wrapped RSA or ECC private key to secure memory for use by this
 * session in future calls to OEMCrypto_PrepAndSignLicenseRequest or
 * OEMCrypto_DeriveKeysFromSessionKey. The wrapped private key will be the
 * one verified and wrapped by OEMCrypto_LoadProvisioning. The private key
 * should be stored in secure memory.
 *
 * If the bit field "allowed_schemes" was wrapped with this RSA key, its
 * value will be loaded and stored with the RSA key, and the key may be used
 * with calls to OEMCrypto_GenerateRSASignature. If there was not a bit field
 * wrapped with the RSA key, the key will be used for
 * OEMCrypto_PrepAndSignLicenseRequest or OEMCrypto_DeriveKeysFromSessionKey
 *
 * @verification
 *   The following checks should be performed. If any check fails, an error is
 *   returned, and the RSA key is not loaded.
 *     1. The wrapped key has a valid signature, as described in
 *        RewrapDeviceRSAKey.
 *     2. The decrypted key is a valid private RSA key.
 *     3. If a value for allowed_schemes is included with the key, it is a
 *        valid value.
 *
 *   @param[in] session: crypto session identifier.
 *   @param[in] key_type: indicates either an RSA or ECC key for devices that
 *      support both.
 *   @param[in] wrapped_private_key: wrapped device private key (RSA or ECC).
 *      This is the wrapped key generated by OEMCrypto_LoadProvisioning.
 *   @param[in] wrapped_private_key_length: length of the wrapped key buffer, in
 *      bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NO_DEVICE_KEY
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_RSA_KEY
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_LoadDRMPrivateKey(OEMCrypto_SESSION session,
                                            OEMCrypto_PrivateKeyType key_type,
                                            const uint8_t* wrapped_private_key,
                                            size_t wrapped_private_key_length);

/**
 * Some platforms do not support keyboxes or OEM Certificates. On those
 * platforms, there is a DRM certificate baked into the OEMCrypto library.
 * This is unusual, and is only available for L3 devices. In order to debug
 * and test those devices, they should be able to switch to the test DRM
 * certificate.
 *
 * Temporarily use the standard test RSA key until the next call to
 * OEMCrypto_Terminate. This allows a standard suite of unit tests to be run
 * on a production device without permanently changing the key. Using the
 * test key is not persistent.
 *
 * The test key can be found in the unit test code, oemcrypto_test.cpp, in
 * PKCS8 form as the constant kTestRSAPKCS8PrivateKeyInfo2_2048.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED devices that use a keybox should
 *         not implement this function
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 10.
 */
OEMCryptoResult OEMCrypto_LoadTestRSAKey(void);

/**
 * The OEMCrypto_GenerateRSASignature method is only used for devices that
 * are CAST receivers. This function is called after
 * OEMCrypto_LoadDRMPrivateKey for the same session.
 *
 * The parameter padding_scheme has two possible legacy values:
 *
 * 0x1 - RSASSA-PSS with SHA1.
 *
 * 0x2 - PKCS1 with block type 1 padding (only).
 *
 * The only supported padding scheme is 0x2 since version 16 of this API. In
 * this second case, the "message" is already a digest, so no further hashing
 * is applied, and the message_length can be no longer than 83 bytes. If the
 * message_length is greater than 83 bytes OEMCrypto_ERROR_SIGNATURE_FAILURE
 * shall be returned.
 *
 * The second padding scheme is for devices that use X509 certificates for
 * authentication. The main example is devices that work as a Cast receiver,
 * like a ChromeCast, not for devices that wish to send to the Cast device,
 * such as almost all Android devices. OEMs that do not support X509
 * certificate authentication need not implement this function and can return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED.
 *
 * @verification
 *   Both the padding_scheme and the RSA key's allowed_schemes must be 0x2. If
 *   not, then the signature is not computed and the error
 *   OEMCrypto_ERROR_INVALID_RSA_KEY is returned.
 *
 * @param[in] session: crypto session identifier.
 * @param[in] message: pointer to memory containing message to be signed.
 * @param[in] message_length: length of the message, in bytes.
 * @param[out] signature: buffer to hold the message signature. On return, it
 *    will contain the message signature generated with the device private RSA
 *    key using RSASSA-PSS. Will be null on the first call in order to find
 *    required buffer size.
 * @param[in,out] signature_length: (in) length of the signature buffer, in
 *    bytes. (out) actual length of the signature
 * @param[in] padding_scheme: specify which scheme to use for the signature.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if the signature buffer is too small.
 * @retval OEMCrypto_ERROR_INVALID_SESSION
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_INVALID_RSA_KEY
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED if algorithm > 0, and the device
 *         does not support that algorithm.
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support message sizes as described in the section
 *   OEMCrypto_ResourceRatingTier.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_GenerateRSASignature(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    uint8_t* signature, size_t* signature_length,
    RSA_Padding_Scheme padding_scheme);

/// @}

/// @addtogroup usage_table
/// @{

/**
 * This creates a new Usage Table Header with no entries. If there is already
 * a generation number stored in secure storage, it will be incremented by 1
 * and used as the new Master Generation Number. This will only be called if
 * the CDM layer finds no existing usage table on the file system. OEMCrypto
 * will encrypt and sign the new, empty, header and return it in the provided
 * buffer.
 *
 * The new entry should be created with a status of kUnused and all times
 * times should be set to 0.
 *
 * Devices that do not implement a Session Usage Table may return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED.
 *
 * @param[out] header_buffer: pointer to memory where encrypted usage table
 *    header is written.
 * @param[in,out] header_buffer_length: (in) length of the header_buffer, in
 *    bytes. (out) actual length of the header_buffer
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if header_buffer_length is too small.
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_CreateUsageTableHeader(uint8_t* header_buffer,
                                                 size_t* header_buffer_length);

/**
 * This loads the Usage Table Header. The buffer's signature is verified and
 * the buffer is decrypted. OEMCrypto will verify the verification string. If
 * the Master Generation Number is more than 1 off, the table is considered
 * bad, the headers are NOT loaded, and the error
 * OEMCrypto_ERROR_GENERATION_SKEW is returned. If the generation number is
 * off by 1, the warning OEMCrypto_WARNING_GENERATION_SKEW is returned but
 * the header is still loaded. This warning may be logged by the CDM layer.
 *
 * @param[in] buffer: pointer to memory containing encrypted usage table header.
 * @param[in] buffer_length: length of the buffer, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED some devices do not implement usage
 *         tables.
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_WARNING_GENERATION_SKEW if the generation number is off
 *         by exactly 1.
 * @retval OEMCrypto_ERROR_GENERATION_SKEW if the generation number is off by
 *         more than 1.
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE if the signature failed.
 * @retval OEMCrypto_ERROR_BAD_MAGIC verification string does not match.
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_LoadUsageTableHeader(const uint8_t* buffer,
                                               size_t buffer_length);

/**
 * This creates a new usage entry. The size of the header will be increased
 * by 8 bytes, and secure volatile memory will be allocated for it. The new
 * entry will be associated with the given session. The status of the new
 * entry will be set to "unused". OEMCrypto will set *usage_entry_number to
 * be the index of the new entry. The first entry created will have index 0.
 * The new entry will be initialized with a generation number equal to the
 * master generation number, which will also be stored in the header's new
 * slot. Then the master generation number will be incremented. Since each
 * entry's generation number is less than the master generation number, the
 * new entry will have a generation number that is larger than all other
 * entries and larger than all previously deleted entries. This helps prevent
 * a rogue application from deleting an entry and then loading an old version
 * of it.
 *
 * If the session already has a usage entry associated with it, the error
 * OEMCrypto_ERROR_MULTIPLE_USAGE_ENTRIES is returned.
 *
 * @param[in] session: handle for the session to be used.
 * @param[out] usage_entry_number: index of new usage entry.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED some devices do not implement usage
 *         tables.
 * @retval OEMCrypto_ERROR_INSUFFICIENT_RESOURCES if there is no room in
 *         memory to increase the size of the usage table header. The CDM layer
 *         can delete some entries and then try again, or it can pass the error
 *         up to the application.
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_MULTIPLE_USAGE_ENTRIES if there already is a usage
 *         entry loaded into this session
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_CreateNewUsageEntry(OEMCrypto_SESSION session,
                                              uint32_t* usage_entry_number);

/**
 * This loads a usage entry saved previously by UpdateUsageEntry. The
 * signature at the beginning of the buffer is verified and the buffer will
 * be decrypted. Then the verification field in the entry will be verified.
 * The index in the entry must match the index passed in. The generation
 * number in the entry will be compared against the entry's corresponding
 * generation number in the header. If it is off by 1, a warning is returned,
 * but the entry is still loaded. This warning may be logged by the CDM
 * layer. If the generation number is off by more than 1, an error is
 * returned and the entry is not loaded.
 *
 * OEMCrypto shall call ODK_ReloadClockValues, as described in "License
 * Duration and Renewal" to set the session's clock values.
 *
 * If the entry is already loaded into another open session, then this fails
 * and returns OEMCrypto_ERROR_INVALID_SESSION. If the session already has a
 * usage entry associated with it, the error
 * OEMCrypto_ERROR_MULTIPLE_USAGE_ENTRIES is returned.
 *
 * Before version API 16, the usage entry stored the time that the license
 * was loaded. This value is now interpreted as the time that the licence
 * request was signed. This can be achieved by simply renaming the field and
 * using the same value when reloading an older entry.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] usage_entry_number: index of existing usage entry.
 * @param[in] buffer: pointer to memory containing encrypted usage table entry.
 * @param[in] buffer_length: length of the buffer, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED some devices do not implement usage
 *         tables.
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE index beyond end of table.
 * @retval OEMCrypto_ERROR_INVALID_SESSION entry associated with another
 *         session or the index is wrong.
 * @retval OEMCrypto_WARNING_GENERATION_SKEW if the generation number is off
 *         by exactly 1.
 * @retval OEMCrypto_ERROR_GENERATION_SKEW if the generation number is off by
 *         more than 1.
 * @retval OEMCrypto_ERROR_SIGNATURE_FAILURE if the signature failed.
 * @retval OEMCrypto_ERROR_BAD_MAGIC verification string does not match.
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 * @retval OEMCrypto_ERROR_MULTIPLE_USAGE_ENTRIES if there already is a usage
 *         entry loaded into this session
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_LoadUsageEntry(OEMCrypto_SESSION session,
                                         uint32_t usage_entry_number,
                                         const uint8_t* buffer,
                                         size_t buffer_length);

/**
 * Updates the session's usage entry and fills buffers with the encrypted and
 * signed entry and usage table header.
 *
 * OEMCrypto shall call ODK_UpdateLastPlaybackTime to update the session's
 * clock values, as discussed in the document "License Duration and Renewal".
 * The values in the session's clock values structure are copied to the usage
 * entry.
 *
 * OEMCrypto shall update all time and status values in the entry, and then
 * increment the entry's generation number. The corresponding generation
 * number in the usage table header is also incremented so that it matches
 * the one in the entry. The master generation number in the usage table
 * header is incremented and the master generation number is copied to secure
 * persistent storage. OEMCrypto will encrypt and sign the entry into the
 * entry_buffer, and it will encrypt and sign the usage table header into the
 * header_buffer. Some actions, such as the first decrypt and deactivating an
 * entry, will also increment the entry's generation number as well as
 * changing the entry's status and time fields. The first decryption will
 * change the status from Inactive to Active, and it will set the time stamp
 * "first decrypt".
 *
 * If the usage entry has the flag ForbidReport set, then the flag is
 * cleared. It is the responsibility of the CDM layer to call this function
 * and save the usage table before the next call to ReportUsage and before
 * the CDM is terminated. Failure to do so will result in generation number
 * skew, which will invalidate all of the usage table.
 *
 * If either entry_buffer_length or header_buffer_length is not large enough,
 * they are set to the needed size, and return OEMCrypto_ERROR_SHORT_BUFFER.
 * In this case, the entry is not updated, ForbidReport is not cleared,
 * generation numbers are not incremented, and no other work is done.
 *
 * @param[in] session: handle for the session to be used.
 * @param[out] header_buffer: pointer to memory where encrypted usage table
 *    header is written.
 * @param[in,out] header_buffer_length: (in) length of the header_buffer, in
 *    bytes. (out) actual length of the header_buffer
 * @param[out] entry_buffer: pointer to memory where encrypted usage table entry
 *    is written.
 * @param[in,out] entry_buffer_length: (in) length of the entry_buffer, in
 *    bytes. (out) actual length of the entry_buffer
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED some devices do not implement usage
 *         tables.
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_UpdateUsageEntry(
    OEMCrypto_SESSION session, OEMCrypto_SharedMemory* header_buffer,
    size_t* header_buffer_length, OEMCrypto_SharedMemory* entry_buffer,
    size_t* entry_buffer_length);

/**
 * This deactivates the usage entry associated with the current session. This
 * means that the status of the usage entry is changed to InactiveUsed if it
 * was Active, or InactiveUnused if it was Unused. This also increments the
 * entry's generation number, and the header's master generation number. The
 * corresponding generation number in the usage table header is also
 * incremented so that it matches the one in the entry. The entry's flag
 * ForbidReport will be set. This flag prevents an application from
 * generating a report of a deactivated license without first saving the
 * entry.
 *
 * OEMCrypto shall call ODK_DeactivateUsageEntry to update the session's
 * clock values, as discussed in the document "License Duration and Renewal".
 *
 * It is allowed to call this function multiple times. If the state is
 * already InactiveUsed or InactiveUnused, then this function does not change
 * the entry or its state.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] pst: pointer to memory containing Provider Session Token.
 * @param[in] pst_length: length of the pst, in bytes.
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT an entry was not created or loaded,
 *         or the pst does not match.
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support  pst sizes of at least 255 bytes.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 16.
 */
OEMCryptoResult OEMCrypto_DeactivateUsageEntry(OEMCrypto_SESSION session,
                                               const uint8_t* pst,
                                               size_t pst_length);

/**
 * All fields of OEMCrypto_PST_Report are in network byte order.
 *
 * If the buffer_length is not sufficient to hold a report structure, set
 * buffer_length and return OEMCrypto_ERROR_SHORT_BUFFER.
 *
 * If an entry was not loaded or created with OEMCrypto_CreateNewUsageEntry
 * or OEMCrypto_LoadUsageEntry, or if the pst does not match that in the
 * entry, return the error OEMCrypto_ERROR_INVALID_CONTEXT.
 *
 * If the usage entry's flag ForbidReport is set, indicating the entry has
 * not been saved since the entry was deactivated, then the error
 * OEMCrypto_ERROR_ENTRY_NEEDS_UPDATE is returned and a report is not
 * generated. Similarly, if any key in the session has been used since the
 * last call to OEMCrypto_UpdateUsageEntry, then the report is not generated,
 * and OEMCrypto returns  the error OEMCrypto_ERROR_ENTRY_NEEDS_UPDATE.
 *
 * The pst_report is filled out by subtracting the times in the Usage Entry
 * from the current time on the secure clock. This design was chosen to avoid
 * a requirement to sync the device's secure clock with any external clock.
 *
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * Valid values for status are:
 *
 *   - 0 = kUnused -- the keys have not been used to decrypt.
 *   - 1 = kActive -- the keys have been used, and have not been deactivated.
 *   - 2 = kInactive - deprecated.  Use kInactiveUsed or kInactiveUnused.
 *   - 3 = kInactiveUsed -- the keys have been marked inactive after being
 *      active.
 *   - 4 = kInactiveUnused -- they keys have been marked inactive, but were
 *      never active.
 * The clock_security_level is reported as follows:
 *
 *   - 0 = Insecure Clock - clock just uses system time.
 *   - 1 = Secure Timer - clock runs from a secure timer which is initialized
 *      from system time when OEMCrypto becomes active and cannot be modified
 *      by user software or the user while OEMCrypto is active. A secure
 *      timer cannot run backwards, even while OEMCrypto is not active.
 *   - 2 = Secure Clock - Real-time clock set from a secure source that
 *      cannot be modified by user software regardless of whether OEMCrypto
 *      is active or inactive. The clock time can only be modified by
 *      tampering with the security software or hardware.
 *   - 3 = Hardware Secure Clock - Real-time clock set from a secure source
 *      that cannot be modified by user software and there are security
 *      features that prevent the user from modifying the clock in hardware,
 *      such as a tamper proof battery.
 * (See drawing in "Widevine Modular DRM Security Integration Guide")
 *
 * After pst_report has been filled in, the HMAC SHA1 signature is computed
 * for the buffer from bytes 20 to the end of the pst field. The signature is
 * computed using the mac_key[client] which is stored in the usage table. The
 * HMAC SHA1 signature is used to prevent a rogue application from using
 * OMECrypto_GenerateSignature to forge a Usage Report.
 *
 * Before version 16 of this API, seconds_since_license_received was reported
 * instead of seconds_since_license_signed. For any practical bookkeeping
 * purposes, these events are essentially at the same time.
 *
 * Devices that do not implement a Session Usage Table may return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] pst: pointer to memory containing Provider Session Token.
 * @param[in] pst_length: length of the pst, in bytes.
 * @param[out] buffer: pointer to buffer in which usage report should be
 *    stored. May be null on the first call in order to find required buffer
 *    size.
 * @param[in,out] buffer_length: (in) length of the report buffer, in bytes.
 *    (out) actual length of the report
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER if report buffer is not large enough
 *         to hold the output report.
 * @retval OEMCrypto_ERROR_INVALID_SESSION no open session with that id.
 * @retval OEMCrypto_ERROR_INVALID_CONTEXT
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_ENTRY_NEEDS_UPDATE if no call to UpdateUsageEntry
 *         since last call to Deactivate or since key use.
 * @retval OEMCrypto_ERROR_WRONG_PST report asked for wrong pst.
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @buffer_size
 *   OEMCrypto shall support  pst sizes of at least 255 bytes.
 *   OEMCrypto shall return OEMCrypto_ERROR_BUFFER_TOO_LARGE if the buffer is
 *   larger than the supported size.
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method changed in API version 13.
 */
OEMCryptoResult OEMCrypto_ReportUsage(OEMCrypto_SESSION session,
                                      const uint8_t* pst, size_t pst_length,
                                      uint8_t* buffer, size_t* buffer_length);

/**
 * Moves the entry associated with the current session from one location in
 * the usage table header to another. This function is used by the CDM layer
 * to defragment the usage table. This does not modify any data in the entry,
 * except the index and the generation number. The index in the session's
 * usage entry will be changed to new_index. The generation number in
 * session's usage entry and in the header for new_index will be increased to
 * the master generation number, and then the master generation number is
 * incremented. If there was an existing entry at the new location, it will
 * be overwritten. It is an error to call this when the entry that was at
 * new_index is associated with a currently open session. In this case, the
 * error code OEMCrypto_ERROR_ENTRY_IN_USE is returned. It is the CDM layer's
 * responsibility to call UpdateUsageEntry after moving an entry. It is an
 * error for new_index to be beyond the end of the existing usage table
 * header.
 *
 * Devices that do not implement a Session Usage Table may return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED.
 *
 * @param[in] session: handle for the session to be used.
 * @param[in] new_index: new index to be used for the session's usage entry
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE
 * @retval OEMCrypto_ERROR_ENTRY_IN_USE
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 13.
 */
OEMCryptoResult OEMCrypto_MoveEntry(OEMCrypto_SESSION session,
                                    uint32_t new_index);

/**
 * This shrinks the usage table and the header. This function is used by the
 * CDM layer after it has  defragmented the usage table and can delete unused
 * entries. It is an error if any open session is associated with an entry
 * that will be erased - the error OEMCrypto_ERROR_ENTRY_IN_USE shall be
 * returned in this case, and the header shall not be modified. If
 * new_entry_count is larger than the current size, then the header is not
 * changed and the error OEMCrypto_ERROR_UNKNOWN_FAILURE is returned. If the
 * header has not been previously loaded, then an error is returned.
 * OEMCrypto will increment the master generation number in the header and
 * store the new value in secure persistent storage. Then, OEMCrypto will
 * encrypt and sign the header into the provided buffer. The generation
 * numbers of all remaining entries will remain unchanged. The next time
 * OEMCrypto_CreateNewUsageEntry is called, the new entry will have an index
 * of new_entry_count.
 *
 * Devices that do not implement a Session Usage Table may return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED.
 *
 * If header_buffer_length is not large enough to hold the new table, it is
 * set to the needed value, the generation number is not  incremented, and
 * OEMCrypto_ERROR_SHORT_BUFFER is returned.
 *
 * If the header has not been loaded or created, return the error
 * OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *
 * @param[in] new_entry_count: number of entries in the to be in the header.
 * @param[out] header_buffer: pointer to memory where encrypted usage table
 *    header is written.
 * @param[in,out] header_buffer_length: (in) length of the header_buffer, in
 *    bytes. (out) actual length of the header_buffer
 *
 * @retval OEMCrypto_SUCCESS success
 * @retval OEMCrypto_ERROR_SHORT_BUFFER
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 * @retval OEMCrypto_ERROR_ENTRY_IN_USE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Usage Table Function" and will not be called simultaneously
 *   with any other function, as if the CDM holds a write lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 13.
 */
OEMCryptoResult OEMCrypto_ShrinkUsageTableHeader(uint32_t new_entry_count,
                                                 uint8_t* header_buffer,
                                                 size_t* header_buffer_length);

/// @}

/// @addtogroup test_verify
/// @{

/**
 * Delete the current SRM. Any valid SRM, regardless of its version number,
 * will be installable after this via OEMCrypto_LoadSRM.
 *
 * This function should not be implemented on production devices, and will
 * only be used to verify unit tests on a test device.
 *
 * @retval OEMCrypto_SUCCESS if the SRM file was deleted.
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED always on production devices.
 *
 * @threading
 *   This is an "Initialization and Termination Function" and will not be
 *   called simultaneously with any other function, as if the CDM holds a write
 *   lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 13.
 */
OEMCryptoResult OEMCrypto_RemoveSRM(void);

/**
 * Returns the type of hash function supported for Full Decrypt Path Testing.
 * A hash type of OEMCrypto_Hash_Not_Supported = 0 means this feature is not
 * supported. OEMCrypto is not required by Google to support this feature,
 * but support will greatly improve automated testing. A hash type of
 * OEMCrypto_CRC_Clear_Buffer = 1 means the device will be able to compute
 * the CRC 32 checksum of the decrypted content in the secure buffer after a
 * call to OEMCrypto_DecryptCENC. Google intends to provide test applications
 * on some platforms, such as Android, that will automate decryption testing
 * using the CRC 32 checksum of all frames in some test content.
 *
 * If an SOC vendor cannot support CRC 32 checksums of decrypted output, but
 * can support some other hash or checksum, then the function should return
 * OEMCrypto_Partner_Defined_Hash = 2 and those partners should modify the
 * test application to compute the appropriate hash. An application that
 * computes the CRC 32 hashes of test content and builds a hash file in the
 * correct format will be provided by Widevine. The source of this
 * application will be provided so that partners may modify it to compute
 * their own hash format and generate their own hashes.
 *
 * @retval OEMCrypto_Hash_Not_Supported = 0;
 * @retval OEMCrypto_CRC_Clear_Buffer = 1;
 * @retval OEMCrypto_Partner_Defined_Hash = 2;
 *
 * @threading
 *   This is a "Property Function" and may be called simultaneously with any
 *   other property function or session function, but not any initialization or
 *   usage table function, as if the CDM holds a read lock on the OEMCrypto
 *   system.
 *
 * @version
 *   This method is new in API version 15.
 */
uint32_t OEMCrypto_SupportsDecryptHash(void);

/**
 * Set the hash value for the next frame to be decrypted. This function is
 * called before the first subsample is passed to OEMCrypto_DecryptCENC, when
 * the subsample_flag has the bit OEMCrypto_FirstSubsample set. The hash is
 * over all of the frame or sample: encrypted and clear subsamples
 * concatenated together, up to, and including the subsample with the
 * subsample_flag having the bit OEMCrypto_LastSubsample set. If hashing the
 * output is not supported, then this will return
 * OEMCrypto_ERROR_NOT_IMPLEMENTED. If the hash is ill formed or there are
 * other error conditions, this returns OEMCrypto_ERROR_UNKNOWN_FAILURE. The
 * length of the hash will be at most 128 bytes, and will be 4 bytes (32
 * bits) for the default CRC32 hash.
 *
 * This may be called before the first call to SelectKey. In that case, this
 * function cannot verify that the key control block allows hash
 * verification. The function DecryptCENC should verify that the key control
 * bit allows hash verification when it is called. If an attempt is made to
 * compute a hash when the selected key does not have the bit
 * Allow_Hash_Verification set, then a hash should not be computed, and
 * OEMCrypto_GetHashErrorCode should return the error
 * OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *
 * OEMCrypto should compute the hash of the frame and then compare it with
 * the correct value. If the values differ, then OEMCrypto should latch in an
 * error and save the frame number of the bad hash. It is allowed for
 * OEMCrypto to postpone computation of the hash until the frame is
 * displayed. This might happen if the actual decryption operation is carried
 * out by a later step in the video pipeline, or if you are using a partner
 * specified hash of the decoded frame. For this reason, an error state must
 * be saved until the call to OEMCrypto_GetHashErrorCode is made.
 *
 * @param[in] session: session id for current decrypt operation
 * @param[in] frame_number: frame number for the recent DecryptCENC sample.
 * @param[in] hash: hash or CRC of previously decrypted frame.
 * @param[in] hash_length: length of hash, in bytes.
 *
 * @retval OEMCrypto_SUCCESS if the hash was set
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED function not implemented
 * @retval OEMCrypto_ERROR_INVALID_SESSION session not open
 * @retval OEMCrypto_ERROR_SHORT_BUFFER hash_length too short for supported
 *         hash type
 * @retval OEMCrypto_ERROR_BUFFER_TOO_LARGE hash_length too long for supported
 *         hash type
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE other error
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 15.
 */
OEMCryptoResult OEMCrypto_SetDecryptHash(OEMCrypto_SESSION session,
                                         uint32_t frame_number,
                                         const uint8_t* hash,
                                         size_t hash_length);

/**
 * If the hash set in OEMCrypto_SetDecryptHash did not match the computed
 * hash, then an error code was saved internally. This function returns that
 * error and the frame number of the bad hash. This will be called
 * periodically, but might not be in sync with the decrypt loop. OEMCrypto
 * shall not reset the error state to "no error" once any frame has failed
 * verification. It should be initialized to "no error" when the session is
 * first opened. If there is more than one bad frame, it is the implementer's
 * choice if it is more useful to return the number of the first bad frame,
 * or the most recent bad frame.
 *
 * If the hash could not be computed -- either because the
 * Allow_Hash_Verification was not set in the key control block, or because
 * there were other issues -- this function should return
 * OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *
 * @param[in] session: session id for operation.
 * @param[out] failed_frame_number: frame number for sample with incorrect hash.
 *
 * @retval OEMCrypto_SUCCESS if all frames have had a correct hash
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_BAD_HASH if any frame had an incorrect hash
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE if the hash could not be computed
 * @retval OEMCrypto_ERROR_SESSION_LOST_STATE
 * @retval OEMCrypto_ERROR_SYSTEM_INVALIDATED
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 15.
 */
OEMCryptoResult OEMCrypto_GetHashErrorCode(OEMCrypto_SESSION session,
                                           uint32_t* failed_frame_number);

/**
 * Allocates a secure buffer and fills out the destination buffer information
 * in output_descriptor. The integer secure_fd may also be set to indicate
 * the source of the buffer. OEMCrypto may use the secure_fd to help track
 * the buffer if it wishes. The unit tests will pass a pointer to the same
 * destination buffer description and the same secure_fd to
 * OEMCrypto_FreeSecureBuffer when the buffer is to be freed.
 *
 * This is especially helpful if the hash functions above are supported. This
 * will only be used by the OEMCrypto unit tests, so we recommend returning
 * OEMCrypto_ERROR_NOT_IMPLEMENTED for production devices if performance is
 * an issue. If OEMCrypto_ERROR_NOT_IMPLEMENTED is returned, then secure
 * buffer unit tests will be skipped.
 *
 * @param[in] session: session id for operation.
 * @param[in] buffer_size: the requested buffer size.
 * @param[out] output_descriptor: the buffer descriptor for the created
 *    buffer. This will be passed into the OEMCrypto_DecryptCENC function.
 * @param[out] secure_fd: a pointer to platform dependent file or buffer
 *    descriptor. This will be passed to OEMCrypto_FreeSecureBuffer.
 *
 * @retval OEMCrypto_SUCCESS if the buffer was created
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_OUTPUT_TOO_LARGE
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 16.
 */
OEMCryptoResult OEMCrypto_AllocateSecureBuffer(
    OEMCrypto_SESSION session, size_t buffer_size,
    OEMCrypto_DestBufferDesc* output_descriptor, int* secure_fd);

/**
 * Frees a secure buffer that had previously been created with
 * OEMCrypto_AllocateSecureBuffer. Any return value except OEMCrypto_SUCCESS
 * will cause the unit test using secure buffers to fail.
 *
 * @param[in] session: session id for operation.
 * @param[out] output_descriptor: the buffer descriptor modified by
 *    OEMCrypto_AllocateSecureBuffer
 * @param[in] secure_fd: The integer returned by OEMCrypto_AllocateSecureBuffer
 *
 * @retval OEMCrypto_SUCCESS if the buffer was freed
 * @retval OEMCrypto_ERROR_NOT_IMPLEMENTED
 * @retval OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * @threading
 *   This is a "Session Function" and may be called simultaneously with session
 *   functions for other sessions but not simultaneously with other functions
 *   for this session. It will not be called simultaneously with initialization
 *   or usage table functions. It is as if the CDM holds a write lock for this
 *   session, and a read lock on the OEMCrypto system.
 *
 * @version
 *   This method is new in API version 16.
 */
OEMCryptoResult OEMCrypto_FreeSecureBuffer(
    OEMCrypto_SESSION session, OEMCrypto_DestBufferDesc* output_descriptor,
    int secure_fd);

/// @}

/****************************************************************************/
/****************************************************************************/
/* The following functions are deprecated.  They are not required for the
 * current version of OEMCrypto. They are being declared here to help with
 * backwards compatibility.
 */
OEMCryptoResult OEMCrypto_GenerateSignature(OEMCrypto_SESSION session,
                                            const uint8_t* message,
                                            size_t message_length,
                                            uint8_t* signature,
                                            size_t* signature_length);

OEMCryptoResult OEMCrypto_RewrapDeviceRSAKey30(
    OEMCrypto_SESSION session, const uint32_t* unaligned_nonce,
    const uint8_t* encrypted_message_key, size_t encrypted_message_key_length,
    const uint8_t* enc_rsa_key, size_t enc_rsa_key_length,
    const uint8_t* enc_rsa_key_iv, uint8_t* wrapped_rsa_key,
    size_t* wrapped_rsa_key_length);

OEMCryptoResult OEMCrypto_RewrapDeviceRSAKey(
    OEMCrypto_SESSION session, const uint8_t* message, size_t message_length,
    const uint8_t* signature, size_t signature_length,
    const uint32_t* unaligned_nonce, const uint8_t* enc_rsa_key,
    size_t enc_rsa_key_length, const uint8_t* enc_rsa_key_iv,
    uint8_t* wrapped_rsa_key, size_t* wrapped_rsa_key_length);

OEMCryptoResult OEMCrypto_UpdateUsageTable(void);

OEMCryptoResult OEMCrypto_DeleteUsageEntry(OEMCrypto_SESSION, const uint8_t*,
                                           size_t, const uint8_t*, size_t,
                                           const uint8_t*, size_t);

OEMCryptoResult OEMCrypto_ForceDeleteUsageEntry(const uint8_t*, size_t);

OEMCryptoResult OEMCrypto_CopyOldUsageEntry(OEMCrypto_SESSION session,
                                            const uint8_t* pst,
                                            size_t pst_length);

OEMCryptoResult OEMCrypto_DeleteOldUsageTable(void);

OEMCryptoResult OEMCrypto_CreateOldUsageEntry(
    uint64_t time_since_license_received, uint64_t time_since_first_decrypt,
    uint64_t time_since_last_decrypt, OEMCrypto_Usage_Entry_Status status,
    uint8_t* server_mac_key, uint8_t* client_mac_key, const uint8_t* pst,
    size_t pst_length);

OEMCryptoResult OEMCrypto_GenerateDerivedKeys_V15(
    OEMCrypto_SESSION session, const uint8_t* mac_key_context,
    uint32_t mac_key_context_length, const uint8_t* enc_key_context,
    uint32_t enc_key_context_length);

typedef struct {
  size_t encrypt;  // number of 16 byte blocks to decrypt.
  size_t skip;     // number of 16 byte blocks to leave in clear.
  size_t offset;   // offset into the pattern in blocks for this call.
} OEMCrypto_CENCEncryptPatternDesc_V15;

OEMCryptoResult OEMCrypto_DecryptCENC_V15(
    OEMCrypto_SESSION session, const uint8_t* data_addr, size_t data_length,
    bool is_encrypted, const uint8_t* iv,
    size_t block_offset,  // used for CTR "cenc" mode only.
    OEMCrypto_DestBufferDesc* out_buffer_descriptor,
    const OEMCrypto_CENCEncryptPatternDesc_V15* pattern,
    uint8_t subsample_flags);

OEMCryptoResult OEMCrypto_GetOEMPublicCertificate_V15(
    OEMCrypto_SESSION session, uint8_t* public_cert,
    size_t* public_cert_length);

OEMCryptoResult OEMCrypto_LoadDeviceRSAKey(OEMCrypto_SESSION session,
                                           const uint8_t* wrapped_rsa_key,
                                           size_t wrapped_rsa_key_length);
/****************************************************************************/
/****************************************************************************/

#ifdef __cplusplus
}
#endif

#endif  // OEMCRYPTO_CENC_H_
