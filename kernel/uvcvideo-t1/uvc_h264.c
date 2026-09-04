// SPDX-License-Identifier: GPL-2.0-or-later
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

#include "uvc_h264.h"

static unsigned int read_le16(const unsigned char *input)
{
	return input[0] | (unsigned int)input[1] << 8;
}

static unsigned int read_le32(const unsigned char *input)
{
	return input[0] | (unsigned int)input[1] << 8 |
	       (unsigned int)input[2] << 16 | (unsigned int)input[3] << 24;
}

int uvc_h264_parse_frame_descriptor(
	const unsigned char *buffer, int buffer_length,
	struct uvc_h264_frame_descriptor *descriptor)
{
	struct uvc_h264_frame_descriptor parsed = { 0 };
	unsigned int pixels;
	unsigned int required_length;
	unsigned int i;

	if (!buffer || !descriptor || buffer_length < 44)
		return -EINVAL;

	parsed.length = buffer[0];
	parsed.interval_count = buffer[43];
	required_length = 44 + 4 * parsed.interval_count;
	if (!parsed.interval_count ||
	    parsed.interval_count > UVC_H264_MAX_INTERVALS ||
	    parsed.length < required_length ||
	    parsed.length > (unsigned int)buffer_length)
		return -EINVAL;

	parsed.width = read_le16(&buffer[4]);
	parsed.height = read_le16(&buffer[6]);
	if (!parsed.width || !parsed.height ||
	    parsed.width > ~0U / parsed.height)
		return -EINVAL;
	pixels = parsed.width * parsed.height;
	if (pixels > ~0U / 2)
		return -EINVAL;

	parsed.index = buffer[3];
	parsed.capabilities = read_le16(&buffer[21]);
	parsed.min_bit_rate = read_le32(&buffer[31]);
	parsed.max_bit_rate = read_le32(&buffer[35]);
	parsed.frame_size = pixels * 2;
	parsed.default_interval = read_le32(&buffer[39]);
	for (i = 0; i < parsed.interval_count; ++i) {
		unsigned int interval = read_le32(&buffer[44 + 4 * i]);

		parsed.intervals[i] = interval ? interval : 1;
	}

	*descriptor = parsed;
	return 0;
}
