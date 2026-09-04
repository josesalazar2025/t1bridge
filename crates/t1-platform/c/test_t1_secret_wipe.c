#include "t1_secret_wipe.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static unsigned int failures;

static void check(int condition, const char *description)
{
	if (condition)
		return;
	fprintf(stderr, "FAIL: %s\n", description);
	++failures;
}

int main(void)
{
	uint8_t bytes[10];
	size_t offset;
	size_t length;
	size_t index;

	for (offset = 0; offset <= sizeof(bytes); ++offset) {
		for (length = 0; length <= sizeof(bytes) - offset; ++length) {
			for (index = 0; index < sizeof(bytes); ++index)
				bytes[index] = UINT8_C(0xa5);
			t1_secret_wipe(bytes + offset, length);
			for (index = 0; index < sizeof(bytes); ++index)
				check(bytes[index] ==
				      ((index >= offset && index < offset + length) ?
				       0 : UINT8_C(0xa5)),
				      "overwrite exactly the requested range");
		}
	}
	t1_secret_wipe(NULL, 0);

	if (failures != 0) {
		fprintf(stderr, "secret wipe: %u tests failed\n", failures);
		return 1;
	}
	puts("secret wipe: all tests passed");
	return 0;
}
