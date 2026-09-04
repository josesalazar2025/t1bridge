#ifndef SEP_ACM_H
#define SEP_ACM_H

#include <stddef.h>
#include <stdint.h>

#include "sep_relay.h"

#define SEP_ACM_COMMAND_HEADER_SIZE 8U
#define SEP_ACM_EXTERNAL_FORM_SIZE 16U
#define SEP_ACM_CONTEXT_CREATE_REPLY_SIZE 17U
#define SEP_ACM_PASSPHRASE_MAX_SIZE 0x80U
#define SEP_ACM_VERIFY_REPLY_CAPACITY 0x1000U
#define SEP_ACM_RELAY_REQUEST UINT8_C(1)

enum sep_acm_result {
	SEP_ACM_OK = 0,
	SEP_ACM_ERROR_ARGUMENT = -1,
	SEP_ACM_ERROR_STATE = -2,
	SEP_ACM_ERROR_RELAY = -3,
	SEP_ACM_ERROR_REPLY = -4,
	SEP_ACM_ERROR_REMOTE = -5,
	SEP_ACM_ERROR_AMBIGUOUS = -6,
};

enum sep_acm_phase {
	SEP_ACM_PHASE_NEW,
	SEP_ACM_PHASE_READY,
	SEP_ACM_PHASE_ACTIVE,
	SEP_ACM_PHASE_FAILED,
};

enum sep_acm_operation {
	SEP_ACM_OPERATION_NONE,
	SEP_ACM_OPERATION_INITIALIZE,
	SEP_ACM_OPERATION_CONTEXT_CREATE,
	SEP_ACM_OPERATION_CONTEXT_DELETE,
	SEP_ACM_OPERATION_CONTEXT_EXTERNALIZE,
	SEP_ACM_OPERATION_CONTAINS_CREDENTIAL,
	SEP_ACM_OPERATION_REPLACE_PASSPHRASE,
	SEP_ACM_OPERATION_VERIFY_ENROLLMENT,
};

struct sep_acm_external_form {
	uint8_t bytes[SEP_ACM_EXTERNAL_FORM_SIZE];
};

struct sep_acm_state {
	struct sep_relay_pending pending;
	enum sep_acm_phase phase;
	enum sep_acm_operation pending_operation;
	struct sep_acm_external_form context;
	uint8_t log_level;
	uint8_t context_externalized;
	uint8_t pending_valid;
};

struct sep_acm_outcome {
	enum sep_acm_operation operation;
	int32_t remote_result;
	uint8_t boolean_valid;
	uint8_t boolean_value;
	uint8_t log_level_valid;
	uint8_t log_level;
};

int sep_acm_state_init(struct sep_acm_state *state);
void sep_acm_state_wipe(struct sep_acm_state *state);
int sep_acm_mark_ambiguous(struct sep_acm_state *state);

int sep_acm_external_form_import(struct sep_acm_external_form *form,
				 const void *input, size_t input_length);
int sep_acm_external_form_export(const struct sep_acm_external_form *form,
				 void *output, size_t output_length);
void sep_acm_external_form_wipe(struct sep_acm_external_form *form);
int sep_acm_export_active_context(const struct sep_acm_state *state,
				  struct sep_acm_external_form *form);

int sep_acm_build_initialize(struct sep_acm_state *state,
			     struct sep_relay_state *relay,
			     uint8_t output[SEP_RELAY_BUFFER_SIZE]);
/* audit_uid is caller-observed; this wire layer never infers it. */
int sep_acm_build_context_create(struct sep_acm_state *state,
				 struct sep_relay_state *relay,
				 uint32_t audit_uid,
				 uint8_t output[SEP_RELAY_BUFFER_SIZE]);
int sep_acm_build_context_delete(struct sep_acm_state *state,
				 struct sep_relay_state *relay,
				 uint8_t output[SEP_RELAY_BUFFER_SIZE]);
int sep_acm_build_context_externalize(
	struct sep_acm_state *state, struct sep_relay_state *relay,
	uint8_t output[SEP_RELAY_BUFFER_SIZE]);
int sep_acm_build_contains_credential(
	struct sep_acm_state *state, struct sep_relay_state *relay,
	uint32_t credential_type, uint32_t credential_scope,
	uint8_t output[SEP_RELAY_BUFFER_SIZE]);
int sep_acm_build_replace_passphrase(
	struct sep_acm_state *state, struct sep_relay_state *relay,
	const void *secret, size_t secret_length, uint32_t credential_scope,
	uint8_t output[SEP_RELAY_BUFFER_SIZE]);
/* keybag_uuid is caller-verified; null selects the unbound preflight. */
int sep_acm_build_verify_enrollment(
	struct sep_acm_state *state, struct sep_relay_state *relay, int preflight,
	const void *keybag_uuid, size_t keybag_uuid_length,
	uint8_t output[SEP_RELAY_BUFFER_SIZE]);

int sep_acm_accept_reply(struct sep_acm_state *state,
			 const struct sep_relay_message *message,
			 struct sep_acm_outcome *outcome);

void sep_acm_wipe_transfer(uint8_t transfer[SEP_RELAY_BUFFER_SIZE]);
const char *sep_acm_result_name(int result);

#endif
