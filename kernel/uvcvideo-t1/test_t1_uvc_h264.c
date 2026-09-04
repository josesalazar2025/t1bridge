// SPDX-License-Identifier: GPL-2.0-or-later
#include "uvc_h264.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void write_le16(unsigned char *output, unsigned int value)
{
	output[0] = value & 0xff;
	output[1] = value >> 8;
}

static void write_le32(unsigned char *output, unsigned int value)
{
	output[0] = value & 0xff;
	output[1] = value >> 8;
	output[2] = value >> 16;
	output[3] = value >> 24;
}

static void valid_descriptor(unsigned char *buffer, unsigned int length)
{
	memset(buffer, 0, length);
	buffer[0] = length;
	buffer[3] = 7;
	write_le16(&buffer[4], 1280);
	write_le16(&buffer[6], 720);
	write_le16(&buffer[21], 3);
	write_le32(&buffer[31], 1000);
	write_le32(&buffer[35], 2000);
	write_le32(&buffer[39], 333333);
	buffer[43] = 1;
	write_le32(&buffer[44], 333333);
}

static void test_valid_descriptor(void)
{
	unsigned char buffer[48];
	struct uvc_h264_frame_descriptor parsed;

	valid_descriptor(buffer, sizeof(buffer));
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == 0);
	assert(parsed.length == sizeof(buffer));
	assert(parsed.index == 7);
	assert(parsed.capabilities == 3);
	assert(parsed.width == 1280);
	assert(parsed.height == 720);
	assert(parsed.frame_size == 1280 * 720 * 2);
	assert(parsed.default_interval == 333333);
	assert(parsed.interval_count == 1);
	assert(parsed.intervals[0] == 333333);
}

static void test_malformed_bounds(void)
{
	unsigned char buffer[48];
	struct uvc_h264_frame_descriptor parsed;

	valid_descriptor(buffer, sizeof(buffer));
	assert(uvc_h264_parse_frame_descriptor(buffer, -1, &parsed) == -EINVAL);
	assert(uvc_h264_parse_frame_descriptor(buffer, 43, &parsed) == -EINVAL);
	buffer[43] = 0;
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == -EINVAL);
	buffer[43] = 2;
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == -EINVAL);
	buffer[43] = 1;
	buffer[0] = 47;
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == -EINVAL);
	buffer[0] = 49;
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == -EINVAL);
	assert(uvc_h264_parse_frame_descriptor(NULL, sizeof(buffer), &parsed) == -EINVAL);
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), NULL) == -EINVAL);
}

static void test_dimensions_and_intervals(void)
{
	unsigned char buffer[48];
	struct uvc_h264_frame_descriptor parsed;

	valid_descriptor(buffer, sizeof(buffer));
	write_le16(&buffer[4], 0);
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == -EINVAL);
	write_le16(&buffer[4], 65535);
	write_le16(&buffer[6], 65535);
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == -EINVAL);

	valid_descriptor(buffer, sizeof(buffer));
	write_le32(&buffer[44], 0);
	assert(uvc_h264_parse_frame_descriptor(buffer, sizeof(buffer), &parsed) == 0);
	assert(parsed.intervals[0] == 1);
}

int main(void)
{
	test_valid_descriptor();
	test_malformed_bounds();
	test_dimensions_and_intervals();
	puts("UVC H.264 descriptor tests passed");
	return 0;
}
