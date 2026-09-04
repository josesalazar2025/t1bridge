#include "t1_secret_wipe.h"

void t1_secret_wipe(void *buffer, size_t size)
{
	volatile unsigned char *bytes = buffer;

	while (size > 0) {
		*bytes = 0;
		++bytes;
		--size;
	}
}
