#ifndef T1BRIDGE_T1_TOUCHBAR_DRM_H
#define T1BRIDGE_T1_TOUCHBAR_DRM_H

#include <stddef.h>
#include <stdint.h>

enum t1_touchbar_drm_status {
	T1_TOUCHBAR_DRM_OK = 0,
	T1_TOUCHBAR_DRM_INVALID_ARGUMENT,
	T1_TOUCHBAR_DRM_DISCOVERY_FAILED,
	T1_TOUCHBAR_DRM_AMBIGUOUS_DEVICE,
	T1_TOUCHBAR_DRM_OPEN_FAILED,
	T1_TOUCHBAR_DRM_WRONG_DEVICE,
	T1_TOUCHBAR_DRM_RESOURCES_FAILED,
	T1_TOUCHBAR_DRM_CONNECTOR_FAILED,
	T1_TOUCHBAR_DRM_WRONG_GEOMETRY,
	T1_TOUCHBAR_DRM_BUFFER_FAILED,
	T1_TOUCHBAR_DRM_MAPPING_FAILED,
	T1_TOUCHBAR_DRM_PRESENT_FAILED,
};

struct t1_touchbar_drm;

struct t1_touchbar_drm_geometry {
	uint32_t width;
	uint32_t height;
	uint32_t stride;
	uint64_t byte_length;
};

struct t1_touchbar_drm_damage_rectangle {
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
};

struct t1_touchbar_drm_clip_rectangle {
	uint32_t x1;
	uint32_t y1;
	uint32_t x2;
	uint32_t y2;
};

/*
 * Discover the only appletbdrm card through sysfs, validate its device number
 * against the dynamically corresponding /dev/dri card, select its connected
 * Touch Bar mode, and create one XRGB8888 dumb scanout buffer.
 */
enum t1_touchbar_drm_status t1_touchbar_drm_open(
	struct t1_touchbar_drm **output,
	struct t1_touchbar_drm_geometry *geometry);

/* Present one complete logical XRGB8888 Touch Bar frame. */
enum t1_touchbar_drm_status t1_touchbar_drm_present(
	struct t1_touchbar_drm *display, const uint8_t *pixels,
	size_t pixel_length);

/* Present only the validated logical rectangles changed by this frame. */
enum t1_touchbar_drm_status t1_touchbar_drm_present_rectangles(
	struct t1_touchbar_drm *display, const uint8_t *pixels,
	size_t pixel_length,
	const struct t1_touchbar_drm_damage_rectangle *rectangles,
	size_t rectangle_count);

void t1_touchbar_drm_close(struct t1_touchbar_drm *display);

const char *t1_touchbar_drm_status_string(
	enum t1_touchbar_drm_status status);

/* Pure helpers used by the native tests and the production presentation path. */
int t1_touchbar_drm_card_name_valid(const char *name);
enum t1_touchbar_drm_status t1_touchbar_drm_validate_mode(
	uint32_t drm_width, uint32_t drm_height,
	struct t1_touchbar_drm_geometry *geometry);
enum t1_touchbar_drm_status t1_touchbar_drm_copy_rotated_xrgb8888(
	uint8_t *destination, size_t destination_length,
	size_t destination_pitch, const uint8_t *source, size_t source_length,
	uint32_t logical_width, uint32_t logical_height);
enum t1_touchbar_drm_status t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(
	uint8_t *destination, size_t destination_length,
	size_t destination_pitch, const uint8_t *source, size_t source_length,
	uint32_t logical_width, uint32_t logical_height,
	const struct t1_touchbar_drm_damage_rectangle *rectangles,
	size_t rectangle_count);
enum t1_touchbar_drm_status t1_touchbar_drm_damage_to_clip(
	const struct t1_touchbar_drm_damage_rectangle *rectangle,
	uint32_t logical_width, uint32_t logical_height,
	struct t1_touchbar_drm_clip_rectangle *clip);

#endif
