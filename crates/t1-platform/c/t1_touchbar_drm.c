#define _GNU_SOURCE

#include "t1_touchbar_drm.h"

#include <dirent.h>
#include <drm/drm.h>
#include <drm/drm_mode.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define T1_DRM_CLASS_DIRECTORY "/sys/class/drm"
#define T1_DRM_DEVICE_DIRECTORY "/dev/dri"
#define T1_DRM_DRIVER_NAME "appletbdrm"
#define T1_DRM_PORTRAIT_WIDTH UINT32_C(60)
#define T1_DRM_PORTRAIT_HEIGHT UINT32_C(2170)
#define T1_DRM_CONNECTED UINT32_C(1)
#define T1_DRM_MAX_OBJECTS UINT32_C(32)
#define T1_DRM_MAX_MAPPING_BYTES (UINT64_C(16) * UINT64_C(1024) * UINT64_C(1024))
#define T1_DRM_QUERY_ATTEMPTS 4
#define T1_DRM_MAX_DAMAGE_RECTANGLES 64

struct t1_touchbar_drm {
	int descriptor;
	uint32_t connector_id;
	uint32_t crtc_id;
	struct drm_mode_modeinfo mode;
	uint32_t dumb_handle;
	uint32_t framebuffer_id;
	uint8_t *mapping;
	size_t mapping_length;
	size_t pitch;
	struct t1_touchbar_drm_geometry geometry;
	int active;
};

static int ioctl_retry(int descriptor, unsigned long request, void *argument)
{
	int result;

	do {
		result = ioctl(descriptor, request, argument);
	} while (result < 0 && errno == EINTR);
	return result;
}

int t1_touchbar_drm_card_name_valid(const char *name)
{
	const unsigned char *cursor;

	if (name == NULL || strncmp(name, "card", 4) != 0 || name[4] == '\0')
		return 0;
	for (cursor = (const unsigned char *)name + 4; *cursor != '\0'; ++cursor) {
		if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9')
			return 0;
	}
	return 1;
}

static int path_for(char *output, size_t capacity, const char *format,
	const char *name)
{
	int length;

	length = snprintf(output, capacity, format, name);
	return length >= 0 && (size_t)length < capacity;
}

static int card_uses_touchbar_driver(const char *name)
{
	char path[PATH_MAX];
	char target[PATH_MAX];
	const char *base;
	ssize_t length;

	if (!path_for(path, sizeof(path), T1_DRM_CLASS_DIRECTORY
	    "/%s/device/driver", name))
		return 0;
	length = readlink(path, target, sizeof(target) - 1);
	if (length < 0 || (size_t)length >= sizeof(target) - 1)
		return 0;
	target[length] = '\0';
	base = strrchr(target, '/');
	base = base == NULL ? target : base + 1;
	return strcmp(base, T1_DRM_DRIVER_NAME) == 0;
}

static enum t1_touchbar_drm_status discover_card(char *name,
	size_t capacity)
{
	DIR *directory;
	struct dirent *entry;
	unsigned int matches = 0;

	directory = opendir(T1_DRM_CLASS_DIRECTORY);
	if (directory == NULL)
		return T1_TOUCHBAR_DRM_DISCOVERY_FAILED;
	errno = 0;
	while ((entry = readdir(directory)) != NULL) {
		if (!t1_touchbar_drm_card_name_valid(entry->d_name) ||
		    !card_uses_touchbar_driver(entry->d_name))
			continue;
		++matches;
		if (matches == 1) {
			if (strlen(entry->d_name) + 1 > capacity) {
				(void)closedir(directory);
				return T1_TOUCHBAR_DRM_DISCOVERY_FAILED;
			}
			(void)strcpy(name, entry->d_name);
		}
	}
	if (errno != 0) {
		(void)closedir(directory);
		return T1_TOUCHBAR_DRM_DISCOVERY_FAILED;
	}
	if (closedir(directory) != 0)
		return T1_TOUCHBAR_DRM_DISCOVERY_FAILED;
	if (matches == 0)
		return T1_TOUCHBAR_DRM_DISCOVERY_FAILED;
	if (matches != 1)
		return T1_TOUCHBAR_DRM_AMBIGUOUS_DEVICE;
	return T1_TOUCHBAR_DRM_OK;
}

static int parse_device_number(const char *name, dev_t *device_number)
{
	char path[PATH_MAX];
	char value[64];
	char trailing;
	unsigned int major_number;
	unsigned int minor_number;
	ssize_t length;
	int descriptor;

	if (!path_for(path, sizeof(path), T1_DRM_CLASS_DIRECTORY "/%s/dev",
	    name))
		return 0;
	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		return 0;
	do {
		length = read(descriptor, value, sizeof(value) - 1);
	} while (length < 0 && errno == EINTR);
	if (close(descriptor) != 0 || length <= 0 ||
	    (size_t)length >= sizeof(value) - 1)
		return 0;
	value[length] = '\0';
	if (sscanf(value, "%u:%u%c", &major_number, &minor_number,
	    &trailing) != 3 || trailing != '\n')
		return 0;
	*device_number = makedev(major_number, minor_number);
	return 1;
}

static enum t1_touchbar_drm_status open_verified_card(const char *name,
	int *output)
{
	char path[PATH_MAX];
	struct stat status;
	dev_t expected;
	int descriptor;

	if (!parse_device_number(name, &expected) ||
	    !path_for(path, sizeof(path), T1_DRM_DEVICE_DIRECTORY "/%s", name))
		return T1_TOUCHBAR_DRM_WRONG_DEVICE;
	descriptor = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		return T1_TOUCHBAR_DRM_OPEN_FAILED;
	if (fstat(descriptor, &status) != 0 || !S_ISCHR(status.st_mode) ||
	    status.st_rdev != expected || !card_uses_touchbar_driver(name)) {
		(void)close(descriptor);
		return T1_TOUCHBAR_DRM_WRONG_DEVICE;
	}
	*output = descriptor;
	return T1_TOUCHBAR_DRM_OK;
}

enum t1_touchbar_drm_status t1_touchbar_drm_validate_mode(
	uint32_t drm_width, uint32_t drm_height,
	struct t1_touchbar_drm_geometry *geometry)
{
	uint64_t stride;
	uint64_t byte_length;

	if (geometry == NULL)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	memset(geometry, 0, sizeof(*geometry));
	if (drm_width != T1_DRM_PORTRAIT_WIDTH ||
	    drm_height != T1_DRM_PORTRAIT_HEIGHT)
		return T1_TOUCHBAR_DRM_WRONG_GEOMETRY;
	stride = (uint64_t)drm_height * UINT64_C(4);
	byte_length = stride * (uint64_t)drm_width;
	if (stride > UINT32_MAX || byte_length > SIZE_MAX)
		return T1_TOUCHBAR_DRM_WRONG_GEOMETRY;
	geometry->width = drm_height;
	geometry->height = drm_width;
	geometry->stride = (uint32_t)stride;
	geometry->byte_length = byte_length;
	return T1_TOUCHBAR_DRM_OK;
}

static enum t1_touchbar_drm_status get_resources(int descriptor,
	uint32_t **crtcs, uint32_t *crtc_count, uint32_t **connectors,
	uint32_t *connector_count)
{
	struct drm_mode_card_res resources;
	uint32_t *new_crtcs = NULL;
	uint32_t *new_connectors = NULL;
	uint32_t crtc_capacity;
	uint32_t connector_capacity;
	unsigned int attempt;

	for (attempt = 0; attempt < T1_DRM_QUERY_ATTEMPTS; ++attempt) {
		memset(&resources, 0, sizeof(resources));
		if (ioctl_retry(descriptor, DRM_IOCTL_MODE_GETRESOURCES,
		    &resources) != 0)
			break;
		if (resources.count_crtcs == 0 || resources.count_connectors == 0 ||
		    resources.count_crtcs > T1_DRM_MAX_OBJECTS ||
		    resources.count_connectors > T1_DRM_MAX_OBJECTS)
			break;
		crtc_capacity = resources.count_crtcs;
		connector_capacity = resources.count_connectors;
		new_crtcs = calloc(crtc_capacity, sizeof(*new_crtcs));
		new_connectors = calloc(connector_capacity,
		    sizeof(*new_connectors));
		if (new_crtcs == NULL || new_connectors == NULL)
			break;
		resources.crtc_id_ptr = (uintptr_t)new_crtcs;
		resources.connector_id_ptr = (uintptr_t)new_connectors;
		/* Do not advertise output arrays that this query does not supply. */
		resources.count_fbs = 0;
		resources.count_encoders = 0;
		if (ioctl_retry(descriptor, DRM_IOCTL_MODE_GETRESOURCES,
		    &resources) == 0 && resources.count_crtcs != 0 &&
		    resources.count_connectors != 0 &&
		    resources.count_crtcs <= crtc_capacity &&
		    resources.count_connectors <= connector_capacity) {
			*crtcs = new_crtcs;
			*connectors = new_connectors;
			*crtc_count = resources.count_crtcs;
			*connector_count = resources.count_connectors;
			return T1_TOUCHBAR_DRM_OK;
		}
		free(new_crtcs);
		free(new_connectors);
		new_crtcs = NULL;
		new_connectors = NULL;
	}
	free(new_crtcs);
	free(new_connectors);
	return T1_TOUCHBAR_DRM_RESOURCES_FAILED;
}

static enum t1_touchbar_drm_status read_connector(int descriptor,
	uint32_t connector_id, struct drm_mode_get_connector *connector,
	struct drm_mode_modeinfo **modes)
{
	struct drm_mode_modeinfo *new_modes = NULL;
	uint32_t *encoders = NULL;
	uint32_t *properties = NULL;
	uint64_t *property_values = NULL;
	uint32_t mode_capacity;
	uint32_t encoder_capacity;
	uint32_t property_capacity;
	unsigned int attempt;

	for (attempt = 0; attempt < T1_DRM_QUERY_ATTEMPTS; ++attempt) {
		memset(connector, 0, sizeof(*connector));
		connector->connector_id = connector_id;
		/* A zero-capacity query asks DRM to probe and report mode counts. */
		if (ioctl_retry(descriptor, DRM_IOCTL_MODE_GETCONNECTOR,
		    connector) != 0 || connector->count_modes == 0 ||
		    connector->count_modes > T1_DRM_MAX_OBJECTS ||
		    connector->count_encoders > T1_DRM_MAX_OBJECTS ||
		    connector->count_props > T1_DRM_MAX_OBJECTS)
			break;
		mode_capacity = connector->count_modes;
		encoder_capacity = connector->count_encoders;
		property_capacity = connector->count_props;
		new_modes = calloc(mode_capacity, sizeof(*new_modes));
		if (encoder_capacity != 0)
			encoders = calloc(encoder_capacity,
			    sizeof(*encoders));
		if (property_capacity != 0) {
			properties = calloc(property_capacity,
			    sizeof(*properties));
			property_values = calloc(property_capacity,
			    sizeof(*property_values));
		}
		if (new_modes == NULL ||
		    (encoder_capacity != 0 && encoders == NULL) ||
		    (property_capacity != 0 &&
		    (properties == NULL || property_values == NULL)))
			break;
		connector->modes_ptr = (uintptr_t)new_modes;
		connector->encoders_ptr = (uintptr_t)encoders;
		connector->props_ptr = (uintptr_t)properties;
		connector->prop_values_ptr = (uintptr_t)property_values;
		if (ioctl_retry(descriptor, DRM_IOCTL_MODE_GETCONNECTOR,
		    connector) == 0 && connector->count_modes != 0 &&
		    connector->count_modes <= mode_capacity &&
		    connector->count_encoders <= encoder_capacity &&
		    connector->count_props <= property_capacity) {
			free(encoders);
			free(properties);
			free(property_values);
			*modes = new_modes;
			return T1_TOUCHBAR_DRM_OK;
		}
		free(new_modes);
		free(encoders);
		free(properties);
		free(property_values);
		new_modes = NULL;
		encoders = NULL;
		properties = NULL;
		property_values = NULL;
	}
	free(new_modes);
	free(encoders);
	free(properties);
	free(property_values);
	return T1_TOUCHBAR_DRM_CONNECTOR_FAILED;
}

static enum t1_touchbar_drm_status select_output(int descriptor,
	uint32_t *connector_ids, uint32_t connector_count,
	uint32_t *connector_id, struct drm_mode_modeinfo *mode,
	struct t1_touchbar_drm_geometry *geometry)
{
	struct drm_mode_get_connector connector;
	struct drm_mode_modeinfo *modes;
	struct drm_mode_modeinfo *candidate;
	uint32_t index;
	uint32_t mode_index;
	unsigned int matches = 0;
	int connector_failure = 0;

	for (index = 0; index < connector_count; ++index) {
		modes = NULL;
		if (read_connector(descriptor, connector_ids[index], &connector,
		    &modes) != T1_TOUCHBAR_DRM_OK) {
			connector_failure = 1;
			free(modes);
			continue;
		}
		candidate = NULL;
		if (connector.connection == T1_DRM_CONNECTED) {
			for (mode_index = 0; mode_index < connector.count_modes;
			    ++mode_index) {
				if (modes[mode_index].hdisplay !=
				    T1_DRM_PORTRAIT_WIDTH ||
				    modes[mode_index].vdisplay !=
				    T1_DRM_PORTRAIT_HEIGHT)
					continue;
				if (candidate == NULL ||
				    (modes[mode_index].type &
				    DRM_MODE_TYPE_PREFERRED) != 0)
					candidate = &modes[mode_index];
			}
		}
		if (candidate != NULL) {
			++matches;
			if (matches == 1) {
				*connector_id = connector.connector_id;
				*mode = *candidate;
			}
		}
		free(modes);
	}
	if (matches == 0 && connector_failure)
		return T1_TOUCHBAR_DRM_CONNECTOR_FAILED;
	if (matches == 0)
		return T1_TOUCHBAR_DRM_WRONG_GEOMETRY;
	if (matches != 1)
		return T1_TOUCHBAR_DRM_AMBIGUOUS_DEVICE;
	return t1_touchbar_drm_validate_mode(mode->hdisplay, mode->vdisplay,
	    geometry);
}

static enum t1_touchbar_drm_status create_scanout(
	struct t1_touchbar_drm *display)
{
	struct drm_mode_create_dumb create;
	struct drm_mode_map_dumb map;
	struct drm_mode_fb_cmd framebuffer;

	memset(&create, 0, sizeof(create));
	create.width = display->mode.hdisplay;
	create.height = display->mode.vdisplay;
	create.bpp = 32;
	if (ioctl_retry(display->descriptor, DRM_IOCTL_MODE_CREATE_DUMB,
	    &create) != 0 || create.handle == 0 ||
	    create.pitch < create.width * UINT32_C(4) || create.size == 0 ||
	    create.size < (uint64_t)create.pitch * create.height ||
	    create.size > T1_DRM_MAX_MAPPING_BYTES || create.size > SIZE_MAX)
		return T1_TOUCHBAR_DRM_BUFFER_FAILED;
	display->dumb_handle = create.handle;
	display->pitch = create.pitch;
	display->mapping_length = (size_t)create.size;

	memset(&map, 0, sizeof(map));
	map.handle = create.handle;
	if (ioctl_retry(display->descriptor, DRM_IOCTL_MODE_MAP_DUMB, &map) != 0 ||
	    map.offset > INT64_MAX)
		return T1_TOUCHBAR_DRM_MAPPING_FAILED;
	display->mapping = mmap(NULL, display->mapping_length,
	    PROT_READ | PROT_WRITE, MAP_SHARED, display->descriptor,
	    (off_t)map.offset);
	if (display->mapping == MAP_FAILED) {
		display->mapping = NULL;
		return T1_TOUCHBAR_DRM_MAPPING_FAILED;
	}
	memset(display->mapping, 0, display->mapping_length);

	memset(&framebuffer, 0, sizeof(framebuffer));
	framebuffer.width = create.width;
	framebuffer.height = create.height;
	framebuffer.pitch = create.pitch;
	framebuffer.bpp = 32;
	framebuffer.depth = 24;
	framebuffer.handle = create.handle;
	if (ioctl_retry(display->descriptor, DRM_IOCTL_MODE_ADDFB,
	    &framebuffer) != 0 || framebuffer.fb_id == 0)
		return T1_TOUCHBAR_DRM_BUFFER_FAILED;
	display->framebuffer_id = framebuffer.fb_id;
	return T1_TOUCHBAR_DRM_OK;
}

static enum t1_touchbar_drm_status validate_frame_layout(
	uint8_t *destination, size_t destination_length,
	size_t destination_pitch, const uint8_t *source, size_t source_length,
	uint32_t logical_width, uint32_t logical_height)
{
	size_t source_pitch;
	size_t required_source;
	size_t required_destination;

	if (destination == NULL || source == NULL || logical_width == 0 ||
	    logical_height == 0 || logical_width > UINT32_MAX / 4 ||
	    logical_height > UINT32_MAX / 4)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	source_pitch = (size_t)logical_width * 4;
	if ((size_t)logical_height > SIZE_MAX / source_pitch)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	required_source = source_pitch * (size_t)logical_height;
	if (source_length != required_source ||
	    destination_pitch < (size_t)logical_height * 4 ||
	    (size_t)logical_width > SIZE_MAX / destination_pitch)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	required_destination = destination_pitch * (size_t)logical_width;
	if (destination_length < required_destination)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	return T1_TOUCHBAR_DRM_OK;
}

static int damage_valid(
	const struct t1_touchbar_drm_damage_rectangle *rectangle,
	uint32_t logical_width, uint32_t logical_height)
{
	return rectangle != NULL && rectangle->width != 0 &&
	    rectangle->height != 0 && rectangle->x < logical_width &&
	    rectangle->y < logical_height &&
	    rectangle->width <= logical_width - rectangle->x &&
	    rectangle->height <= logical_height - rectangle->y;
}

enum t1_touchbar_drm_status t1_touchbar_drm_damage_to_clip(
	const struct t1_touchbar_drm_damage_rectangle *rectangle,
	uint32_t logical_width, uint32_t logical_height,
	struct t1_touchbar_drm_clip_rectangle *clip)
{
	uint32_t right;
	uint32_t bottom;

	if (clip == NULL)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	memset(clip, 0, sizeof(*clip));
	if (!damage_valid(rectangle, logical_width, logical_height))
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	right = rectangle->x + rectangle->width;
	bottom = rectangle->y + rectangle->height;
	clip->x1 = logical_height - bottom;
	clip->y1 = rectangle->x;
	clip->x2 = logical_height - rectangle->y;
	clip->y2 = right;
	return T1_TOUCHBAR_DRM_OK;
}

enum t1_touchbar_drm_status t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(
	uint8_t *destination, size_t destination_length,
	size_t destination_pitch, const uint8_t *source, size_t source_length,
	uint32_t logical_width, uint32_t logical_height,
	const struct t1_touchbar_drm_damage_rectangle *rectangles,
	size_t rectangle_count)
{
	size_t source_pitch;
	size_t source_offset;
	size_t destination_offset;
	size_t index;
	uint32_t right;
	uint32_t bottom;
	uint32_t x;
	uint32_t y;
	enum t1_touchbar_drm_status status;

	status = validate_frame_layout(destination, destination_length,
	    destination_pitch, source, source_length, logical_width,
	    logical_height);
	if (status != T1_TOUCHBAR_DRM_OK || rectangles == NULL ||
	    rectangle_count == 0 ||
	    rectangle_count > T1_DRM_MAX_DAMAGE_RECTANGLES)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	for (index = 0; index < rectangle_count; ++index) {
		if (!damage_valid(&rectangles[index], logical_width,
		    logical_height))
			return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	}

	source_pitch = (size_t)logical_width * 4;
	for (index = 0; index < rectangle_count; ++index) {
		right = rectangles[index].x + rectangles[index].width;
		bottom = rectangles[index].y + rectangles[index].height;
		for (y = rectangles[index].y; y < bottom; ++y) {
			for (x = rectangles[index].x; x < right; ++x) {
				source_offset = (size_t)y * source_pitch +
				    (size_t)x * 4;
				destination_offset = (size_t)x * destination_pitch +
				    ((size_t)logical_height - 1 - y) * 4;
				memcpy(destination + destination_offset,
				    source + source_offset, 4);
			}
		}
	}
	return T1_TOUCHBAR_DRM_OK;
}

enum t1_touchbar_drm_status t1_touchbar_drm_copy_rotated_xrgb8888(
	uint8_t *destination, size_t destination_length,
	size_t destination_pitch, const uint8_t *source, size_t source_length,
	uint32_t logical_width, uint32_t logical_height)
{
	const struct t1_touchbar_drm_damage_rectangle full = {
		0, 0, logical_width, logical_height
	};

	return t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(destination,
	    destination_length, destination_pitch, source, source_length,
	    logical_width, logical_height, &full, 1);
}

enum t1_touchbar_drm_status t1_touchbar_drm_open(
	struct t1_touchbar_drm **output,
	struct t1_touchbar_drm_geometry *geometry)
{
	struct t1_touchbar_drm *display;
	enum t1_touchbar_drm_status status;
	char card_name[64];
	uint32_t *crtcs = NULL;
	uint32_t *connectors = NULL;
	uint32_t crtc_count = 0;
	uint32_t connector_count = 0;

	if (output == NULL || geometry == NULL)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	*output = NULL;
	memset(geometry, 0, sizeof(*geometry));
	status = discover_card(card_name, sizeof(card_name));
	if (status != T1_TOUCHBAR_DRM_OK)
		return status;
	display = calloc(1, sizeof(*display));
	if (display == NULL)
		return T1_TOUCHBAR_DRM_OPEN_FAILED;
	display->descriptor = -1;
	status = open_verified_card(card_name, &display->descriptor);
	if (status != T1_TOUCHBAR_DRM_OK)
		goto failed;
	status = get_resources(display->descriptor, &crtcs, &crtc_count,
	    &connectors, &connector_count);
	if (status != T1_TOUCHBAR_DRM_OK)
		goto failed;
	status = select_output(display->descriptor, connectors, connector_count,
	    &display->connector_id, &display->mode, &display->geometry);
	if (status != T1_TOUCHBAR_DRM_OK)
		goto failed;
	if (crtc_count == 0) {
		status = T1_TOUCHBAR_DRM_RESOURCES_FAILED;
		goto failed;
	}
	display->crtc_id = crtcs[0];
	status = create_scanout(display);
	if (status != T1_TOUCHBAR_DRM_OK)
		goto failed;
	free(crtcs);
	free(connectors);
	*geometry = display->geometry;
	*output = display;
	return T1_TOUCHBAR_DRM_OK;

failed:
	free(crtcs);
	free(connectors);
	t1_touchbar_drm_close(display);
	return status;
}

enum t1_touchbar_drm_status t1_touchbar_drm_present(
	struct t1_touchbar_drm *display, const uint8_t *pixels,
	size_t pixel_length)
{
	struct t1_touchbar_drm_damage_rectangle full;

	if (display == NULL)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	full.x = 0;
	full.y = 0;
	full.width = display->geometry.width;
	full.height = display->geometry.height;
	return t1_touchbar_drm_present_rectangles(display, pixels, pixel_length,
	    &full, 1);
}

enum t1_touchbar_drm_status t1_touchbar_drm_present_rectangles(
	struct t1_touchbar_drm *display, const uint8_t *pixels,
	size_t pixel_length,
	const struct t1_touchbar_drm_damage_rectangle *rectangles,
	size_t rectangle_count)
{
	struct drm_mode_crtc crtc;
	struct drm_mode_fb_dirty_cmd dirty;
	struct drm_clip_rect clips[T1_DRM_MAX_DAMAGE_RECTANGLES];
	struct t1_touchbar_drm_clip_rectangle mapped;
	struct t1_touchbar_drm_damage_rectangle full;
	enum t1_touchbar_drm_status status;
	size_t index;

	if (display == NULL || display->mapping == NULL || pixels == NULL ||
	    rectangles == NULL || rectangle_count == 0 ||
	    rectangle_count > T1_DRM_MAX_DAMAGE_RECTANGLES)
		return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
	for (index = 0; index < rectangle_count; ++index) {
		status = t1_touchbar_drm_damage_to_clip(&rectangles[index],
		    display->geometry.width, display->geometry.height, &mapped);
		if (status != T1_TOUCHBAR_DRM_OK || mapped.x2 > USHRT_MAX ||
		    mapped.y2 > USHRT_MAX)
			return T1_TOUCHBAR_DRM_INVALID_ARGUMENT;
		clips[index].x1 = (unsigned short)mapped.x1;
		clips[index].y1 = (unsigned short)mapped.y1;
		clips[index].x2 = (unsigned short)mapped.x2;
		clips[index].y2 = (unsigned short)mapped.y2;
	}
	if (!display->active) {
		full.x = 0;
		full.y = 0;
		full.width = display->geometry.width;
		full.height = display->geometry.height;
		status = t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(
		    display->mapping, display->mapping_length, display->pitch,
		    pixels, pixel_length, display->geometry.width,
		    display->geometry.height, &full, 1);
		if (status != T1_TOUCHBAR_DRM_OK)
			return status;
		memset(&crtc, 0, sizeof(crtc));
		crtc.set_connectors_ptr = (uintptr_t)&display->connector_id;
		crtc.count_connectors = 1;
		crtc.crtc_id = display->crtc_id;
		crtc.fb_id = display->framebuffer_id;
		crtc.mode_valid = 1;
		crtc.mode = display->mode;
		if (ioctl_retry(display->descriptor, DRM_IOCTL_MODE_SETCRTC,
		    &crtc) != 0)
			return T1_TOUCHBAR_DRM_PRESENT_FAILED;
		display->active = 1;
		return T1_TOUCHBAR_DRM_OK;
	}
	status = t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(
	    display->mapping, display->mapping_length, display->pitch, pixels,
	    pixel_length, display->geometry.width, display->geometry.height,
	    rectangles, rectangle_count);
	if (status != T1_TOUCHBAR_DRM_OK)
		return status;
	memset(&dirty, 0, sizeof(dirty));
	dirty.fb_id = display->framebuffer_id;
	dirty.num_clips = (uint32_t)rectangle_count;
	dirty.clips_ptr = (uintptr_t)clips;
	if (ioctl_retry(display->descriptor, DRM_IOCTL_MODE_DIRTYFB,
	    &dirty) != 0)
		return T1_TOUCHBAR_DRM_PRESENT_FAILED;
	return T1_TOUCHBAR_DRM_OK;
}

void t1_touchbar_drm_close(struct t1_touchbar_drm *display)
{
	struct drm_mode_destroy_dumb destroy;
	uint32_t framebuffer_id;

	if (display == NULL)
		return;
	if (display->mapping != NULL)
		(void)munmap(display->mapping, display->mapping_length);
	if (display->descriptor >= 0 && display->framebuffer_id != 0) {
		framebuffer_id = display->framebuffer_id;
		(void)ioctl_retry(display->descriptor, DRM_IOCTL_MODE_RMFB,
		    &framebuffer_id);
	}
	if (display->descriptor >= 0 && display->dumb_handle != 0) {
		memset(&destroy, 0, sizeof(destroy));
		destroy.handle = display->dumb_handle;
		(void)ioctl_retry(display->descriptor,
		    DRM_IOCTL_MODE_DESTROY_DUMB, &destroy);
	}
	if (display->descriptor >= 0)
		(void)close(display->descriptor);
	free(display);
}

const char *t1_touchbar_drm_status_string(
	enum t1_touchbar_drm_status status)
{
	switch (status) {
	case T1_TOUCHBAR_DRM_OK:
		return "Touch Bar DRM operation succeeded";
	case T1_TOUCHBAR_DRM_INVALID_ARGUMENT:
		return "invalid Touch Bar DRM argument";
	case T1_TOUCHBAR_DRM_DISCOVERY_FAILED:
		return "Touch Bar DRM device was not found";
	case T1_TOUCHBAR_DRM_AMBIGUOUS_DEVICE:
		return "multiple Touch Bar DRM devices were found";
	case T1_TOUCHBAR_DRM_OPEN_FAILED:
		return "Touch Bar DRM device could not be opened";
	case T1_TOUCHBAR_DRM_WRONG_DEVICE:
		return "Touch Bar DRM device identity changed during discovery";
	case T1_TOUCHBAR_DRM_RESOURCES_FAILED:
		return "Touch Bar DRM resources could not be read";
	case T1_TOUCHBAR_DRM_CONNECTOR_FAILED:
		return "Touch Bar DRM connector could not be read";
	case T1_TOUCHBAR_DRM_WRONG_GEOMETRY:
		return "Touch Bar DRM geometry is unsupported";
	case T1_TOUCHBAR_DRM_BUFFER_FAILED:
		return "Touch Bar DRM scanout buffer setup failed";
	case T1_TOUCHBAR_DRM_MAPPING_FAILED:
		return "Touch Bar DRM scanout mapping failed";
	case T1_TOUCHBAR_DRM_PRESENT_FAILED:
		return "Touch Bar DRM frame presentation failed";
	}
	return "unknown Touch Bar DRM failure";
}
