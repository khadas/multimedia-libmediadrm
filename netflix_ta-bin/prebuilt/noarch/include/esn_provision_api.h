/*
 * ESN key provisioning API
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ESN_PROVISION_API_H_
#define _ESN_PROVISION_API_H_

#define ESN_API_SUCCESS					0
#define ESN_API_FAIL					-1

#define PROVISION_KEY_CHECKSUM_LENGTH                  	32
#define PROVOSION_KEY_MAX_ENSID				42

int esnkeybox_provision(char *file);
int esnkeybox_esnid_get(uint8_t* esnid);
int esnkeybox_esn_remove(void);
int esnkeybox_checksum(uint8_t* checksum);
int esnkeybox_query(uint32_t* key_size);

#endif /* _ESN_PROVISION_API_H_ */

#ifdef __cplusplus
}
#endif
