// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef UVC_H264_H
#define UVC_H264_H

#define UVC_H264_MAX_INTERVALS 52

struct uvc_h264_frame_descriptor {
	unsigned int length;
	unsigned int index;
	unsigned int capabilities;
	unsigned int width;
	unsigned int height;
	unsigned int min_bit_rate;
	unsigned int max_bit_rate;
	unsigned int frame_size;
	unsigned int default_interval;
	unsigned int interval_count;
	unsigned int intervals[UVC_H264_MAX_INTERVALS];
};

int uvc_h264_parse_frame_descriptor(
	const unsigned char *buffer, int buffer_length,
	struct uvc_h264_frame_descriptor *descriptor);

#endif
