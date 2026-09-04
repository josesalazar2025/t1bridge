#include "t1_ncm_ready.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define EXPECT(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
			#condition); \
		exit(1); \
	} \
} while (0)

struct fake_state {
	uint32_t first_index;
	uint32_t second_index;
	uint64_t now;
	uint64_t clock_step;
	unsigned int discover_calls;
	unsigned int set_up_calls;
	unsigned int ready_calls;
	unsigned int wait_calls;
	unsigned int ready_after;
	uint32_t activated_index;
	uint32_t inspected_index;
	int discover_result;
	int second_discover_result;
	int set_up_result;
	int ready_result;
	int clock_result;
	int wait_result;
};

static int fake_discover(void *context, uint32_t *interface_index)
{
	struct fake_state *state = context;
	int result;

	state->discover_calls++;
	result = state->discover_calls == 1 ? state->discover_result :
		state->second_discover_result;
	*interface_index = state->discover_calls == 1 ? state->first_index :
		state->second_index;
	return result;
}

static int fake_set_up(void *context, uint32_t interface_index)
{
	struct fake_state *state = context;

	state->set_up_calls++;
	state->activated_index = interface_index;
	return state->set_up_result;
}

static int fake_is_ready(void *context, uint32_t interface_index)
{
	struct fake_state *state = context;

	state->ready_calls++;
	state->inspected_index = interface_index;
	if (state->ready_result != 0)
		return state->ready_result;
	return state->ready_calls >= state->ready_after ? 1 : 0;
}

static int fake_monotonic_ms(void *context, uint64_t *milliseconds)
{
	struct fake_state *state = context;

	if (state->clock_result != 0)
		return state->clock_result;
	*milliseconds = state->now;
	state->now += state->clock_step;
	return 0;
}

static int fake_wait_ms(void *context, uint32_t milliseconds)
{
	struct fake_state *state = context;

	state->wait_calls++;
	state->now += milliseconds;
	return state->wait_result;
}

static struct t1_ncm_ready_ops fake_ops(struct fake_state *state)
{
	const struct t1_ncm_ready_ops ops = {
		.context = state,
		.discover = fake_discover,
		.set_up = fake_set_up,
		.is_ready = fake_is_ready,
		.monotonic_ms = fake_monotonic_ms,
		.wait_ms = fake_wait_ms,
	};

	return ops;
}

static struct fake_state valid_state(void)
{
	const struct fake_state state = {
		.first_index = 41,
		.second_index = 41,
		.ready_after = 1,
	};

	return state;
}

static void test_success_uses_one_validated_index(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	state.ready_after = 3;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_OK);
	EXPECT(state.discover_calls == 2);
	EXPECT(state.set_up_calls == 1);
	EXPECT(state.ready_calls == 3);
	EXPECT(state.wait_calls == 2);
	EXPECT(state.activated_index == 41);
	EXPECT(state.inspected_index == 41);
}

static void test_discovery_fails_before_mutation(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	state.discover_result = -1;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_DISCOVERY_FAILED);
	EXPECT(state.set_up_calls == 0);
	EXPECT(state.ready_calls == 0);
	state = valid_state();
	state.first_index = 0;
	ops = fake_ops(&state);
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_DISCOVERY_FAILED);
	EXPECT(state.set_up_calls == 0);
	state = valid_state();
	state.first_index = 42;
	ops = fake_ops(&state);
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_DISCOVERY_FAILED);
	EXPECT(state.set_up_calls == 0);
}

static void test_link_and_inspection_fail_closed(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	state.set_up_result = -1;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_LINK_UP_FAILED);
	EXPECT(state.ready_calls == 0);
	state = valid_state();
	state.ready_result = -1;
	ops = fake_ops(&state);
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_INSPECTION_FAILED);
	EXPECT(state.discover_calls == 1);
}

static void test_wait_is_bounded(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	state.ready_after = UINT32_MAX;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_TIMEOUT);
	EXPECT(state.set_up_calls == 1);
	EXPECT(state.ready_calls ==
		T1_NCM_READY_TIMEOUT_MS / T1_NCM_READY_RETRY_MS);
	EXPECT(state.wait_calls == state.ready_calls);
	EXPECT(state.now == T1_NCM_READY_TIMEOUT_MS);
}

static void test_clock_and_wait_failures_are_terminal(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	state.clock_result = -1;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_CLOCK_FAILED);
	EXPECT(state.discover_calls == 0);
	state = valid_state();
	state.ready_after = 2;
	state.wait_result = -1;
	ops = fake_ops(&state);
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_WAIT_FAILED);
	EXPECT(state.discover_calls == 1);
	EXPECT(state.ready_calls == 1);
}

static void test_revalidation_rejects_device_change(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	state.second_index = 42;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_DEVICE_CHANGED);
	state = valid_state();
	state.second_discover_result = -1;
	ops = fake_ops(&state);
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_DEVICE_CHANGED);
}

static void test_invalid_ops_are_rejected(void)
{
	struct fake_state state = valid_state();
	struct t1_ncm_ready_ops ops = fake_ops(&state);

	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, NULL) ==
		T1_NCM_READY_INVALID_ARGUMENT);
	ops.set_up = NULL;
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(41, &ops) ==
		T1_NCM_READY_INVALID_ARGUMENT);
	ops = fake_ops(&state);
	EXPECT(t1_ncm_ready_prepare_for_index_with_ops(0, &ops) ==
		T1_NCM_READY_INVALID_ARGUMENT);
}

int main(void)
{
	test_success_uses_one_validated_index();
	test_discovery_fails_before_mutation();
	test_link_and_inspection_fail_closed();
	test_wait_is_bounded();
	test_clock_and_wait_failures_are_terminal();
	test_revalidation_rejects_device_change();
	test_invalid_ops_are_rejected();
	puts("t1_ncm_ready tests passed");
	return 0;
}
