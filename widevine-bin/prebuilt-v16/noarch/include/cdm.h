// Copyright 2018 Google LLC. All Rights Reserved. This file and proprietary
// source code may only be used and distributed under the Widevine Master
// License Agreement.
// Based on the EME draft spec from 2016 June 10.
// http://www.w3.org/TR/2016/WD-encrypted-media-20160610/"
#ifndef WVCDM_CDM_CDM_H_
#define WVCDM_CDM_CDM_H_

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

// Define CDM_EXPORT to export functionality across shared library boundaries.
#if defined(_WIN32)
#  if defined(CDM_IMPLEMENTATION)
#    define CDM_EXPORT __declspec(dllexport)
#  else
#    define CDM_EXPORT __declspec(dllimport)
#  endif  // defined(CDM_IMPLEMENTATION)
#else     // defined(_WIN32)
#  if defined(CDM_IMPLEMENTATION)
#    define CDM_EXPORT __attribute__((visibility("default")))
#  else
#    define CDM_EXPORT
#  endif
#endif  // defined(_WIN32)

namespace widevine {

class CDM_EXPORT ITimerClient {
 public:
  // Called by ITimer when a timer expires.
  virtual void onTimerExpired(void* context) = 0;

 protected:
  ITimerClient() {}
  virtual ~ITimerClient() {}
};

class CDM_EXPORT Cdm : public ITimerClient {
 public:
  // Session types defined by EME.
  enum SessionType : int32_t {
    kTemporary = 0,
    kPersistentLicense = 1,
    kPersistent = kPersistentLicense,  // deprecated name from June 1 draft
    kPersistentUsageRecord = 2,
  };

  // Message types defined by EME.
  enum MessageType : int32_t {
    kLicenseRequest = 0,
    kLicenseRenewal = 1,
    kLicenseRelease = 2,
    kIndividualizationRequest = 3,  // Not used. Direct Individualization
                                    // is used instead of App-Assisted
  };

  // Status codes returned by CDM functions.
  //
  enum Status : int32_t {
    kSuccess = 0,

    // These are analogous to the exceptions defined in the EME specification.
    // Client implementations that support the EME API should pass these
    // directly to the client application.
    // Note: kTypeError replaced kInvalidAccess in the 6/1/2015 EME spec.
    kTypeError = 1,
    kNotSupported = 2,
    kInvalidState = 3,
    kQuotaExceeded = 4,

    // These are additional codes defined by Widevine. In client implementations
    // that support the EME API, these codes should be handled in the system
    // layer. If it is necessary to notify the client application of one of
    // these statuses, it should be mapped to one of the exception codes defined
    // in the EME specification. Some of these errors are considered
    // "recoverable" in that there are specific known remedies that the client
    // may take in response to them. See the Integration Guide for further
    // information.
    kNeedsDeviceCertificate = 101,  // Recoverable
    kSessionNotFound = 102,
    kDecryptError = 103,
    kNoKey = 104,
    kKeyUsageBlockedByPolicy = 105,
    kRangeError = 106,
    kResourceContention = 107,       // Recoverable
    kSessionStateLost = 108,         // Recoverable
    kSystemStateLost = 109,          // Recoverable
    kOutputTooLarge = 110,           // Recoverable
    kNeedsServiceCertificate = 111,  // Recoverable

    // This covers errors that we do not expect (see logs for details):
    kUnexpectedError = 99999,
  };

  // These are the init data types defined by EME.
  enum InitDataType : int32_t {
    kCenc = 0,
    kKeyIds = 1,  // NOTE: not supported by Widevine at this time
    kWebM = 2,

    // This type is not defined by EME but is supported by Widevine
    kHls = 10000,
  };

  // These are the crypto schemes supported by CENC 3.0.
  enum EncryptionScheme : int32_t {
    kClear = 0,
    kAesCtr = 1,  // AES-CTR, for use with the "cenc" schema
    kAesCbc = 2,  // AES-CBC, for use with the "cbcs" schema
  };

  // These are key statuses defined by EME.
  enum KeyStatus : int32_t {
    kUsable = 0,
    kExpired = 1,
    kOutputRestricted = 2,
    kOutputNotAllowed = kOutputRestricted,  // deprecated name from June 1 draft
    kStatusPending = 3,
    kInternalError = 4,
    kReleased = 5,
  };

  // These are the possible HDCP levels supported by Widevine.
  // For ease of comparison, these values are kept in ascending order by version
  // number.
  enum HdcpVersion : int32_t {
    kHdcp1_x = 0,
    kHdcp2_0 = 1,
    kHdcp2_1 = 2,
    kHdcp2_2 = 3,
    kHdcp2_3 = 4,
  };

  // Permissible usages for a key. Returned as a set of flags; multiple
  // flags may be set. The specific settings are defined in the license
  // and the OEMCrypto Key Control Block. The CDM uses settings in the
  // license to derive these flags.
  typedef uint32_t KeyAllowedUsageFlags;
  static const KeyAllowedUsageFlags kAllowNone = 0;
  static const KeyAllowedUsageFlags kAllowDecryptToClearBuffer = 1;
  static const KeyAllowedUsageFlags kAllowDecryptToSecureBuffer = 2;
  static const KeyAllowedUsageFlags kAllowGenericEncrypt = 4;
  static const KeyAllowedUsageFlags kAllowGenericDecrypt = 8;
  static const KeyAllowedUsageFlags kAllowGenericSign = 16;
  static const KeyAllowedUsageFlags kAllowGenericSignatureVerify = 32;

  // These are defined by Widevine.  The CDM can be configured to decrypt in
  // three modes (dependent on OEMCrypto support).
  enum SecureOutputType : int32_t {
    // Data is decrypted to an opaque handle.
    // Translates to OEMCrypto's OEMCrypto_BufferType_Secure.
    kOpaqueHandle = 0,

    // Decrypted data never returned to the caller, but is decoded and rendered
    // by OEMCrypto.
    // Translates to OEMCrypto's OEMCrypto_BufferType_Direct.
    kDirectRender = 1,

    // There is no secure output available, so all data is decrypted into a
    // clear buffer in main memory.
    // Translates to OEMCrypto's OEMCrypto_BufferType_Clear.
    kNoSecureOutput = 2,
  };

  // Logging levels defined by Widevine.
  // See Cdm::initialize().
  enum LogLevel : int32_t {
    kSilent = -1,
    kErrors = 0,
    kWarnings = 1,
    kInfo = 2,
    kDebug = 3,
    kVerbose = 4,
  };

  // Types of service defined by Widevine.
  // The service certificate installation methods - Cdm::setServiceCertificate()
  // and Cdm::parseAndLoadServiceCertificateResponse() - use these to identify
  // which service the certificate is intended for.
  enum ServiceRole : int32_t {
    kAllServices = 0,
    kProvisioningService = 1,
    kLicensingService = 2,
  };

  // These are the available Widevine robustness levels.
  enum RobustnessLevel : int32_t {
    kL1 = 1,
    kL2 = 2,
    kL3 = 3,
  };

  // A map of key statuses.
  // See Cdm::getKeyStatuses().
  typedef std::map<std::string, KeyStatus> KeyStatusMap;

  // An event listener interface provided by the application and attached to
  // each CDM session.
  // See Cdm::createSession().
  class IEventListener {
   public:
    // A message (license request, renewal, etc.) to be dispatched to the
    // application's license server.
    // The response, if successful, should be provided back to the CDM via a
    // call to Cdm::update().
    virtual void onMessage(const std::string& session_id,
                           MessageType message_type,
                           const std::string& message) = 0;

    // There has been a change in the keys in the session or their status.
    virtual void onKeyStatusesChange(const std::string& session_id,
                                     bool has_new_usable_key) = 0;

    // A remove() operation has been completed.
    virtual void onRemoveComplete(const std::string& session_id) = 0;

   protected:
    IEventListener() {}
    virtual ~IEventListener() {}
  };

  // A storage interface provided by the application. This defines the "origin"
  // that the CDM will operate in by the files it can access.  Passing different
  // IStorage instances to Cdm::create will cause those CDM instances to be in
  // different "origins" as defined by the IStorage instance.  For example,
  // different IStorage instances could be tied to different folders for
  // different origins.
  //
  // It is important for multi-origin hosts to verify the application's origin.
  // This ensures that the application does not access files from another
  // origin.
  //
  // NOTE: It is important for users of your application to be able to clear
  // stored data.  Also, browsers or other multi-application systems should
  // store data separately per-app or per-origin.
  // See http://www.w3.org/TR/encrypted-media/#privacy-storedinfo.
  class IStorage {
   public:
    virtual bool read(const std::string& name, std::string* data) = 0;
    virtual bool write(const std::string& name, const std::string& data) = 0;
    virtual bool exists(const std::string& name) = 0;
    virtual bool remove(const std::string& name) = 0;

    // Returns the size of the given file. If the file does not exist or any
    // other error occurs, this should return a negative number.
    virtual int32_t size(const std::string& name) = 0;

    // Populates |file_names| with the name of each file in the file system.
    // This is assumed to be a flat filename space (top level directory is
    // unnamed, and there are no subdirectories).
    virtual bool list(std::vector<std::string>* file_names) = 0;

   protected:
    IStorage() {}
    virtual ~IStorage() {}
  };

  // A clock interface provided by the application, independent of CDM
  // instances.
  // See Cdm::initialize().
  class IClock {
   public:
    // Returns the current time in milliseconds since 1970 UTC.
    virtual int64_t now() = 0;

   protected:
    IClock() {}
    virtual ~IClock() {}
  };

  // A timer interface provided by the application, independent of CDM
  // instances.
  // See Cdm::initialize().
  // Implementations of this class only need to deal with at most one
  // outstanding timer per IClient at a time. It is an error for setTimeout() to
  // be called while there is already a timer running for that client. It is
  // recommended for implementers of this class to cancel the preexisting timer
  // and start the new timer if this erroneous situation occurs.
  // Timers are non-repeating. If the CDM wants to repeat a timer, it will call
  // setTimeout() again inside the timeout callback.
  class ITimer {
   public:
    // This typedef is for backward compatibility with v3.0.0.
    typedef ITimerClient IClient;

    // Call |client->onTimerExpired(context)| after a delay of |delay_ms| ms.
    virtual void setTimeout(int64_t delay_ms, IClient* client,
                            void* context) = 0;

    // Cancel the timer associated with |client|.
    virtual void cancel(IClient* client) = 0;

   protected:
    ITimer() {}
    virtual ~ITimer() {}
  };

  // Client information, provided by the application, independent of CDM
  // instances.
  // See Cdm::initialize().
  // These parameters end up as client identification in license requests.
  // All fields may be used by a license server proxy to drive business logic.
  // Some fields are required (indicated below), but please fill out as many
  // as make sense for your application.
  // No user-identifying information may be put in these fields!
  struct ClientInfo {
    // The name of the product or application, e.g. "TurtleTube"
    // Required.
    std::string product_name;

    // The name of the company who makes the device, e.g. "Kubrick, Inc."
    // Required.
    std::string company_name;

    // The name of the device, e.g. "HAL"
    std::string device_name;

    // The device model, e.g. "HAL 9000"
    // Required.
    std::string model_name;

    // The architecture of the device, e.g. "x86-64"
    std::string arch_name;

    // Information about the build of the browser, application, or platform into
    // which the CDM is integrated, e.g. "v2.71828, 2038-01-19-03:14:07"
    std::string build_info;
  };

  // Initialize the CDM library and provide access to platform services.
  // All platform interfaces are required. It is the responsibility of the host
  // platform to ensure that the objects passed into this method remain valid
  // for the lifetime of the CDM library.
  // Logging is controlled by |verbosity|.
  // Must be called and must return kSuccess before create() is called.
  static Status initialize(SecureOutputType secure_output_type,
                           const ClientInfo& client_info, IStorage* storage,
                           IClock* clock, ITimer* timer, LogLevel verbosity);

  // This is a variant of the above function that allows the caller to pass a
  // Sandbox ID. Platforms that use Sandbox IDs should use this initalize()
  // function instead of the previous one. Platforms that do not use Sandbox IDs
  // should not use this version of initialize().
  static Status initialize(SecureOutputType secure_output_type,
                           const ClientInfo& client_info, IStorage* storage,
                           IClock* clock, ITimer* timer, LogLevel verbosity,
                           const std::string& sandbox_id);

  // Query the CDM library version.
  static const char* version();

  // Constructs a new CDM instance.
  // initialize() must be called first and must return kSuccess before a CDM
  // instance may be constructed.
  // The CDM may notify of events at any time via the provided |listener|,
  // which may not be NULL.
  // |storage| defines the storage to use for this instance.  By providing
  // different objects here for different origins, this parameter can be used to
  // provide per-origin storage. It may not be NULL.
  // If |privacy_mode| is true, service certificates are required and will be
  // used to encrypt messages to the license server.
  // By using service certificates to encrypt communication with the license
  // server, device-identifying information cannot be extracted from the
  // license exchange process by an intermediate layer between the CDM and
  // the server.
  // This is particularly useful for browser environments, but is recommended
  // for use whenever possible.
  static Cdm* create(IEventListener* listener, IStorage* storage,
                     bool privacy_mode);

  // This is a variant of the above function that allows the caller to specify
  // that the IStorage should be treated as read-only. Passing true for this
  // parameter will cause the Widevine CE CDM to prevent attempts to modify any
  // data in the IStorage. Note that this is *not* the expected operation mode
  // for most clients and will likely lead to playback failures. It should only
  // be used in cases where read-only certificates and licenses have been
  // pre-loaded on a device, such as the preloaded licenses in ATSC 3.
  //
  // It is not possible to mix read-only and non-read-only files in the same
  // IStorage instance. A separate CDM with a separate IStorage pointing to the
  // non-read-only files should be created with the read-only flag omitted or
  // set to false.
  static Cdm* create(IEventListener* listener, IStorage* storage,
                     bool privacy_mode, bool storage_is_read_only);

  virtual ~Cdm() {}

  // The following three methods relate to service certificates. A service
  // certificate holds the RSA public key for a server, as well as other fields
  // needed for provisioning. Service certificates are mandatory if privacy mode
  // is turned on, as they are used to encrypt portions of outgoing messages to
  // the provisioning and licensing servers.
  // If a provisioning service certificate has not been installed before
  // generating a provisioning request, a default certificate that only works
  // with the Widevine-hosted provisioning service will be used.
  // It is an error to generate a licensing request while privacy mode is
  // turned on without installing a service certificate for the licensing
  // service first.

  // Installs a service certificate from a data buffer.
  // This is used when the system or application already knows the certificate
  // of the service it wishes to communicate with, either because it is baked
  // into the software or because it was previously cached after a call to
  // Cdm::parseAndLoadServiceCertificateResponse().
  // If this method returns |Status::kSuccess|, the service certificate was
  // installed successfully.
  // The certificate is installed only for the service given by |role|. If the
  // role |ServiceRole::kAllServices| is given, it is installed for all
  // services.
  virtual Status setServiceCertificate(ServiceRole role,
                                       const std::string& certificate) = 0;

  // Generate a Service Certificate Request message.
  // This is used to fetch a service certificate from the license server.
  // It is needed in cases where the system or application does not have
  // a service certificate for the license server already.
  virtual Status getServiceCertificateRequest(std::string* message) = 0;

  // Parse a Service Certificate Response message, extracting the certificate
  // from the message and installing it into the CDM.
  // This is used when fetching a service certificate from the license server.
  // A request should be generated by getServiceCertificateRequest() and sent
  // to the license server.  The server's response should be passed into this
  // method.
  // If this method returns |Status::kSuccess|, the service certificate was
  // installed successfully.
  // If a pointer to a string is passed in the |certificate| parameter, this
  // method will fill it with the extracted certificate.  This certificate
  // string may be used with future CDM instances as the input to
  // setServiceCertificate().  This avoids needing to make a call to the license
  // server to get the certificate.  The |certificate| argument may be NULL if
  // you do not want to take advantage of this.
  // The certificate is installed only for the service given by |role|.  If the
  // role |ServiceRole::kAllServices| is given, it is installed for all
  // services.
  virtual Status parseAndLoadServiceCertificateResponse(
      ServiceRole role, const std::string& response,
      std::string* certificate) = 0;

  // Returns the robustness level of the device, as reported by OEMCrypto. Note
  // that this function is *not* cryptographically secure and it should only be
  // relied upon for informational purposes (e.g. determining which content to
  // show in the UI) and not security purposes. (e.g. determining which content
  // to allow the device to play) *Only* secure communication between OEMCrypto
  // and the license service should be used to make security decisions.
  virtual Status getRobustnessLevel(RobustnessLevel* level) = 0;

  // Returns the resource rating tier of the device, as reported by OEMCrypto.
  virtual Status getResourceRatingTier(uint32_t* tier) = 0;

  // Retrieves the build information for the underlying OEMCrypto
  // implementation.
  virtual Status getOemCryptoBuildInfo(std::string* build_info) = 0;

  // Determine if the device has a Device Certificate (for the current origin).
  // The Device Certificate is origin-specific, and the origin is
  // dertermined by the CDM's current IStorage object.
  virtual bool isProvisioned() = 0;

  // Creates a Provisioning Request message.
  // This is used to provision the device.  The request should be sent to the
  // provisioning server and the response given to handleProvisioningResponse().
  virtual Status getProvisioningRequest(std::string* request) = 0;

  // Handles a provisioning response and provisions the device.  If this returns
  // success, the device will now be provisioned.
  virtual Status handleProvisioningResponse(const std::string& response) = 0;

  // Remove the device's Device Certificate (for the current origin).
  // The Device Certificate is origin-specific, and the origin is
  // determined by the CDM's current IStorage object.
  virtual Status removeProvisioning() = 0;

  // Get the current list of offline licenses on the system.
  // License storage is origin-specific, and the origin is determined by the
  // CDM's current IStorage object.
  virtual Status listStoredLicenses(std::vector<std::string>* key_set_ids) = 0;

  // Get the current list of secure-stop licenses on the system.
  // License storage is origin-specific, and the origin is determined by the
  // CDM's current IStorage object. ksids receives list of KSIDs representing
  // usage records or secure-stop licenses.
  virtual Status listUsageRecords(std::vector<std::string>* ksids) = 0;

  // Delete the usage record for the given key_set_id.
  // Usage info storage is origin-specific, and the origin is determined by the
  // CDM's current IStorage object.
  virtual Status deleteUsageRecord(const std::string& key_set_id) = 0;

  // Delete all usage records for the current origin.
  // Usage info storage is origin-specific, and the origin is determined by the
  // CDM's current IStorage object.
  virtual Status deleteAllUsageRecords() = 0;

  // Checks whether the device is capable of supporting a given HDCP version.
  // If successful, |key_status| is set to either kUsable or kOutputRestricted.
  virtual Status getStatusForHdcpVersion(HdcpVersion hdcp,
                                         KeyStatus* key_status) = 0;

  // Creates a new session.
  // Do not use this to load an existing persistent session (use load()).
  // If successful, the session ID is returned via |session_id|.
  virtual Status createSession(SessionType session_type,
                               std::string* session_id) = 0;

  // Generates a request based on the initData.
  // The request will be provided via a synchronous call to
  // IEventListener::onMessage().
  // This is done so that license requests and renewals follow the same flow.
  virtual Status generateRequest(const std::string& session_id,
                                 InitDataType init_data_type,
                                 const std::string& init_data) = 0;

  // Loads an existing persisted session from storage.
  virtual Status load(const std::string& session_id) = 0;

  // Provides messages, including licenses, to the CDM.
  // If the message is a successful response to a release message, stored
  // session data will be removed for the session.
  virtual Status update(const std::string& session_id,
                        const std::string& response) = 0;

  // Loads the entitled keys embedded in |init_data| into the session identified
  // by |session_id|. This function is only used when using entitlement
  // licenses for key rotation.
  virtual Status loadEmbeddedKeys(const std::string& session_id,
                                  InitDataType init_data_type,
                                  const std::string& init_data) = 0;

  // The time, in milliseconds since 1970 UTC, after which the key(s) in the
  // session will no longer be usable to decrypt media data, or -1 if no such
  // time exists.
  virtual Status getExpiration(const std::string& session_id,
                               int64_t* expiration) = 0;

  // A map of known key IDs to the current status of the associated key.
  virtual Status getKeyStatuses(const std::string& session_id,
                                KeyStatusMap* key_statuses) = 0;

  // Gets the permitted usage for a specific key by ID.
  virtual Status getKeyAllowedUsages(const std::string& session_id,
                                     const std::string& key_id,
                                     KeyAllowedUsageFlags* usage_flags) = 0;

  // Gets the permitted usage for a specific key by ID.
  // Search for key across all known sessions.  If there are keys in separate
  // sessions that match the given key_id, return kTypeError unless all such
  // keys have identical Allowed Usage settings.
  virtual Status getKeyAllowedUsages(const std::string& key_id,
                                     KeyAllowedUsageFlags* usage_flags) = 0;

  // Indicates that the application no longer needs the session and the CDM
  // should release any resources associated with it and close it.
  // Does not generate release messages for persistent sessions.
  // Does not remove stored session data for persistent sessions.
  virtual Status close(const std::string& session_id) = 0;

  // Removes stored session data associated with the session.
  // The session must be loaded before it can be removed.
  // Generates release messages, which must be delivered to the license server.
  // A reply from the license server must be provided via update() before the
  // session is fully removed.
  virtual Status remove(const std::string& session_id) = 0;

  // Removes stored session data associated with the session.
  // The session must be loaded before it can be removed.
  // Unlike remove(), this method does not generate a release message. The
  // stored data is removed immediately. The session is closed if this function
  // returns successfully.
  // Generally, callers should not use this method, as it prevents usage data
  // from being gathered and it does not allow the license's release to be
  // tracked by the server. Most callers will want to use remove(), which
  // generates a release request. However, this method is provided for
  // applications that have a specific need to release licenses without a server
  // roundtrip and are aware of the costs of doing so.
  // There is no EME equivalent to this method. EME specifies that removal
  // should require a release request, as is done by the remove() method.
  virtual Status forceRemove(const std::string& session_id) = 0;

  // Describes a repeating pattern as defined by the CENC 3.0 standard. A
  // CENC 3.0 pattern consists of a number of encrypted blocks followed by a
  // number of clear blocks, after which it repeats.
  struct Pattern {
   public:
    Pattern() : encrypted_blocks(0), clear_blocks(0) {}

    Pattern(uint32_t encrypt, uint32_t clear)
        : encrypted_blocks(encrypt), clear_blocks(clear) {}

    // The number of crypto blocks that are encrypted and therefore need to be
    // decrypted.
    uint32_t encrypted_blocks;

    // The number of crypto blocks that are not encrypted and therefore should
    // be skipped when doing decryption.
    uint32_t clear_blocks;
  };

  struct Subsample {
   public:
    Subsample() : clear_bytes(0), protected_bytes(0) {}

    // The number of bytes of data that are not protected and therefore should
    // be copied unchanged when doing decryption. The clear bytes come before
    // the protected bytes in the subsample.
    uint32_t clear_bytes;

    // The number of bytes of data that are protected and therefore should be
    // considered for decryption. Depending on the pattern, these bytes may all
    // be decrypted or only some of them may be. The protected bytes come after
    // the clear bytes in the subsample.
    uint32_t protected_bytes;
  };

  struct InputBuffer {
   public:
    InputBuffer()
        : iv(nullptr),
          iv_length(0),
          data(nullptr),
          data_length(0),
          subsamples(nullptr),
          subsamples_length(0) {}

    // These fields are treated as an array of bytes, with the |iv| pointer
    // pointing to the first byte and containing |iv_length| number of bytes.
    // These should be the bytes of the initial IV that should be used to
    // decrypt this sample.
    //
    // |iv_length| must be 16 if the sample contains any protected data. If the
    // content contains an 8-byte IV, it is the responsibility of the caller to
    // expand it to 16 bytes following the method in the ISO-CENC standard.
    const uint8_t* iv;
    uint32_t iv_length;

    // These fields are treated as an array of bytes, with the |data| pointer
    // pointing to the first byte and containing |data_length| number of bytes.
    // This data should be ready to be decrypted with no further processing. If
    // the data is coming from a format that requires processing before
    // decryption, that processing needs to happen before the data is passed in
    // here. For example, content coming from HLS will need to have its extra
    // start code emulation prevention removed before it is passed to the
    // Widevine CE CDM.
    const uint8_t* data;
    uint32_t data_length;

    // These fields are treated as an array of Subsample structs, with the
    // |subsamples| pointer pointing to the first Subsample and containing
    // |samples_length| number of entries. These structs describe all the
    // ISO-CENC subsamples that make up the sample.
    //
    // The sum of all the |clear_bytes| and |protected_bytes| in all the
    // subsamples must equal the |data_length| field.
    const Subsample* subsamples;
    uint32_t subsamples_length;
  };

  struct OutputBuffer {
    OutputBuffer() : data(nullptr), data_offset(0), data_length(0) {}

    // The type of value stored in this pointer depends on the secure output
    // type passed to Cdm::initialize() and the |is_secure| field of the
    // DecryptionBatch.
    //
    // If |is_secure| is false or the secure output type is kNoSecureOutput,
    // this is a memory address in main memory.
    // If |is_secure| is true and the secure output type is kOpaqueHandle,
    // this is an opaque handle.
    // If |is_secure| is true and the secure output type is kDirectRender,
    // this is ignored.
    //
    // See also the SecureOutputType argument to initialize().
    void* data;

    // An offset applied to the output address inside OEMCrypto.
    // Useful when |data| is an opaque handle rather than a memory address.
    uint32_t data_offset;

    // The maximum amount of data that can be decrypted to the |data| buffer.
    // Must be at least as large as the input buffer's |data_length| plus the
    // bytes that will be skipped by |data_offset|.
    uint32_t data_length;
  };

  struct Sample {
   public:
    Sample() : input(), output() {}

    // These structs describe the protected input data of the sample and the
    // output buffer that decrypted data should be written to.
    InputBuffer input;
    OutputBuffer output;
  };

  struct DecryptionBatch {
   public:
    DecryptionBatch()
        : samples(nullptr),
          samples_length(0),
          key_id(nullptr),
          key_id_length(0),
          pattern(),
          is_secure(false),
          encryption_scheme(kClear),
          is_video(true) {}

    // These fields are treated as an array of Sample structs, with the
    // |samples| pointer pointing to the first Sample and containing
    // |samples_length| number of entries. These structs describe all the data
    // that is going to be decrypted. You can pass as many samples to the CDM as
    // you want, but be aware that passing more samples than your OEMCrypto
    // implementation can handle in one decrypt call is inefficient, as the CDM
    // will have to do work to break the data up into smaller pieces.
    const Sample* samples;
    uint32_t samples_length;

    // These fields are treated as an array of bytes, with the |key_id| pointer
    // pointing to the first byte and containing |key_id_length| number of
    // bytes. These should be the bytes of the Key ID of the key that should be
    // used to decrypt the |samples|.
    const uint8_t* key_id;
    uint32_t key_id_length;

    // Describes the repeating pattern with which the content was encrypted. If
    // left at its default value of (0,0), patterns will be disabled. Should
    // only be changed for content that uses patterns, such as for CENC 3.0
    // "cbcs" content or for HLS content.
    Pattern pattern;

    // Indicates whether the OutputBuffers in the Samples are secure outputs or
    // not. False for clear buffers, true otherwise.
    // Must be false if the secure output type is kNoSecureOutput.
    // See also the SecureOutputType argument to initialize().
    bool is_secure;

    // Specifies the encryption scheme, if any, to be used to decrypt the data.
    // When set to kClear, decryption will copy the input data directly to the
    // output buffer. This is necessary for secure output types, where the
    // output buffer cannot be directly accessed above the CDM.
    EncryptionScheme encryption_scheme;

    // Used by secure output type kDirectRender, where the secure hardware must
    // decode and render the decrypted content:
    bool is_video;
  };

  // Decrypt the samples contained in the DecryptionBatch |batch| from their
  // InputBuffer to their OutputBuffer. The |key_id| field of |batch|
  // must refer to a key that is already loaded in some session.
  virtual Status decrypt(const DecryptionBatch& batch) = 0;

  // Decrypt the samples contained in the DecryptionBatch |batch| from their
  // InputBuffer to their OutputBuffer. Decryption will be attempted in the
  // session identified by |session_id|, regardless of whether the |key_id|
  // field of |batch| refers to a key loaded in that session. If |key_id| refers
  // to a key that is not loaded in the given session, decryption will fail.
  //
  // This overload is used when platforms need to play clear content through the
  // secure path before a key is loaded.
  virtual Status decrypt(const std::string& session_id,
                         const DecryptionBatch& batch) = 0;

  // Sets a value in the custom app settings.  These are settings
  // that are sent with any message to the license server.  These methods
  // should only be used by advanced users maintaining existing systems.
  // The |key| cannot be empty.
  virtual Status setAppParameter(const std::string& key,
                                 const std::string& value) = 0;

  // Gets the current value in the custom app settings.  If the key is
  // not present, then kTypeError is returned.  The |key| cannot be
  // empty.  |result| cannot be null.  See setAppParameter().
  virtual Status getAppParameter(const std::string& key,
                                 std::string* result) = 0;

  // Removes the value in the custom app settings.  If the key is not
  // present, then kTypeError is returned.  The |key| cannot be empty.
  // See setAppParameter().
  virtual Status removeAppParameter(const std::string& key) = 0;

  // Clears all the values in the custom app settings.  See setAppParameter().
  virtual Status clearAppParameters() = 0;

  // Generic crypto - functions for applying crypto operations to
  // app-level data (outside the content stream).

  enum GenericEncryptionAlgorithmType : int32_t {
    kEncryptionAlgorithmUnknown,
    kEncryptionAlgorithmAesCbc128,
  };

  enum GenericSigningAlgorithmType : int32_t {
    kSigningAlgorithmUnknown,
    kSigningAlgorithmHmacSha256
  };

  // Encrypts a buffer of app-level data.
  virtual Status genericEncrypt(const std::string& session_id,
                                const std::string& in_buffer,
                                const std::string& key_id,
                                const std::string& iv,
                                GenericEncryptionAlgorithmType algorithm,
                                std::string* out_buffer) = 0;

  // Decrypts a buffer of app-level data.
  virtual Status genericDecrypt(const std::string& session_id,
                                const std::string& in_buffer,
                                const std::string& key_id,
                                const std::string& iv,
                                GenericEncryptionAlgorithmType algorithm,
                                std::string* out_buffer) = 0;

  // Signs a buffer of app-level data.
  virtual Status genericSign(const std::string& session_id,
                             const std::string& message,
                             const std::string& key_id,
                             GenericSigningAlgorithmType algorithm,
                             std::string* signature) = 0;

  // Verifies the signature on a buffer of app-level data.
  // Returns kSuccess if signature is verified, otherwise returns kDecryptError.
  virtual Status genericVerify(const std::string& session_id,
                               const std::string& message,
                               const std::string& key_id,
                               GenericSigningAlgorithmType algorithm,
                               const std::string& signature) = 0;

  // Enable enforcement of Video Resolution Constraints.
  // This function should be called during session startup and any time
  // the resolution of the video stream changes. The resolution passed in should
  // be the resolution of the content being played, not the output resolution of
  // the device.
  // Video resolutions in the license policy are stored as 32-bit values
  // representing the total number of pixels. If the product of |width| and
  // |height| is greater than or equal to 2^32, this will return kRangeError.
  virtual Status setVideoResolution(const std::string& session_id,
                                    uint32_t width, uint32_t height) = 0;

  // Retrieve the metrics gathered by this CDM instance.
  // The Widevine CE CDM gathers metrics about the time taken to perform various
  // computations, as well as their error codes. This method allows platforms
  // and apps to gather these metrics to send them back to Google for analysis.
  virtual Status getMetrics(std::string* serialized_metrics) = 0;

 protected:
  Cdm() {}
};

}  // namespace widevine

#endif  // WVCDM_CDM_CDM_H_
