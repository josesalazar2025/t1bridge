#include "t1_touchbar_drm.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned int failures;

static void check(int condition, const char *description)
{
	if (condition)
		return;
	fprintf(stderr, "FAIL: %s\n", description);
	++failures;
}

static void test_card_names(void)
{
	check(t1_touchbar_drm_card_name_valid("card7"), "accept numbered card");
	check(t1_touchbar_drm_card_name_valid("card123"), "accept numbered card");
	check(!t1_touchbar_drm_card_name_valid(NULL), "reject null card name");
	check(!t1_touchbar_drm_card_name_valid("card"), "reject missing number");
	check(!t1_touchbar_drm_card_name_valid("renderD128"),
	    "reject render node");
	check(!t1_touchbar_drm_card_name_valid("card7-DP-1"),
	    "reject connector name");
	check(!t1_touchbar_drm_card_name_valid("../card7"),
	    "reject path traversal");
}

static void test_geometry(void)
{
	struct t1_touchbar_drm_geometry geometry;

	memset(&geometry, 0xa5, sizeof(geometry));
	check(t1_touchbar_drm_validate_mode(60, 2170, &geometry) ==
	    T1_TOUCHBAR_DRM_OK, "accept exact portrait mode");
	check(geometry.width == 2170 && geometry.height == 60,
	    "report logical landscape geometry");
	check(geometry.stride == 8680 && geometry.byte_length == 520800,
	    "report exact XRGB frame layout");
	check(t1_touchbar_drm_validate_mode(2170, 60, &geometry) ==
	    T1_TOUCHBAR_DRM_WRONG_GEOMETRY,
	    "reject already-rotated DRM mode");
	check(geometry.width == 0 && geometry.height == 0 &&
	    geometry.stride == 0 && geometry.byte_length == 0,
	    "clear geometry on rejection");
	check(t1_touchbar_drm_validate_mode(60, 2169, &geometry) ==
	    T1_TOUCHBAR_DRM_WRONG_GEOMETRY,
	    "reject near-match geometry");
	check(t1_touchbar_drm_validate_mode(60, 2170, NULL) ==
	    T1_TOUCHBAR_DRM_INVALID_ARGUMENT, "reject null geometry output");
}

static void set_pixel(uint8_t *pixels, size_t offset, uint8_t value)
{
	pixels[offset] = value;
	pixels[offset + 1] = (uint8_t)(value + 1);
	pixels[offset + 2] = (uint8_t)(value + 2);
	pixels[offset + 3] = 0;
}

static void test_rotation(void)
{
	uint8_t source[24];
	uint8_t destination[36];
	uint8_t expected[36];
	size_t x;
	size_t y;
	size_t source_offset;
	size_t destination_offset;

	memset(source, 0, sizeof(source));
	for (y = 0; y < 2; ++y) {
		for (x = 0; x < 3; ++x)
			set_pixel(source, (y * 3 + x) * 4,
			    (uint8_t)(10 + y * 3 + x));
	}
	memset(destination, 0xa5, sizeof(destination));
	memset(expected, 0xa5, sizeof(expected));
	for (y = 0; y < 2; ++y) {
		for (x = 0; x < 3; ++x) {
			source_offset = (y * 3 + x) * 4;
			destination_offset = x * 12 + (1 - y) * 4;
			memcpy(expected + destination_offset,
			    source + source_offset, 4);
		}
	}
	check(t1_touchbar_drm_copy_rotated_xrgb8888(destination,
	    sizeof(destination), 12, source, sizeof(source), 3, 2) ==
	    T1_TOUCHBAR_DRM_OK, "rotate a padded synthetic frame");
	check(memcmp(destination, expected, sizeof(destination)) == 0,
	    "apply the proven short-axis flip without changing XRGB bytes");
	check(destination[8] == 0xa5 && destination[9] == 0xa5 &&
	    destination[10] == 0xa5 && destination[11] == 0xa5,
	    "leave destination pitch padding untouched");

	memset(destination, 0xa5, sizeof(destination));
	check(t1_touchbar_drm_copy_rotated_xrgb8888(destination,
	    sizeof(destination), 12, source, sizeof(source) - 1, 3, 2) ==
	    T1_TOUCHBAR_DRM_INVALID_ARGUMENT, "reject short source");
	check(destination[0] == 0xa5, "reject before mutating destination");
	check(t1_touchbar_drm_copy_rotated_xrgb8888(destination,
	    sizeof(destination) - 1, 12, source, sizeof(source), 3, 2) ==
	    T1_TOUCHBAR_DRM_INVALID_ARGUMENT, "reject short destination");
	check(t1_touchbar_drm_copy_rotated_xrgb8888(destination,
	    sizeof(destination), 7, source, sizeof(source), 3, 2) ==
	    T1_TOUCHBAR_DRM_INVALID_ARGUMENT, "reject short pitch");
	check(t1_touchbar_drm_copy_rotated_xrgb8888(NULL,
	    sizeof(destination), 12, source, sizeof(source), 3, 2) ==
	    T1_TOUCHBAR_DRM_INVALID_ARGUMENT, "reject null destination");
}

static void test_partial_rotation(void)
{
	uint8_t source[24];
	uint8_t destination[36];
	uint8_t expected[36];
	struct t1_touchbar_drm_damage_rectangle rectangles[2];
	size_t y;

	for (y = 0; y < sizeof(source); ++y)
		source[y] = (uint8_t)(y + 1);
	memset(destination, 0xa5, sizeof(destination));
	memset(expected, 0xa5, sizeof(expected));
	rectangles[0].x = 1;
	rectangles[0].y = 0;
	rectangles[0].width = 1;
	rectangles[0].height = 2;
	memcpy(expected + 12, source + 16, 4);
	memcpy(expected + 16, source + 4, 4);
	check(t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(destination,
	    sizeof(destination), 12, source, sizeof(source), 3, 2,
	    rectangles, 1) == T1_TOUCHBAR_DRM_OK,
	    "rotate only one logical damage rectangle");
	check(memcmp(destination, expected, sizeof(destination)) == 0,
	    "leave every pixel outside partial damage untouched");

	memset(destination, 0xa5, sizeof(destination));
	rectangles[1].x = 3;
	rectangles[1].y = 0;
	rectangles[1].width = 1;
	rectangles[1].height = 1;
	check(t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(destination,
	    sizeof(destination), 12, source, sizeof(source), 3, 2,
	    rectangles, 2) == T1_TOUCHBAR_DRM_INVALID_ARGUMENT,
	    "reject all rectangles before copying any of them");
	check(destination[12] == 0xa5,
	    "invalid later damage leaves the destination untouched");
	rectangles[0].width = 0;
	check(t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(destination,
	    sizeof(destination), 12, source, sizeof(source), 3, 2,
	    rectangles, 1) == T1_TOUCHBAR_DRM_INVALID_ARGUMENT,
	    "reject zero-width damage");
	check(t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(destination,
	    sizeof(destination), 12, source, sizeof(source), 3, 2,
	    rectangles, 0) == T1_TOUCHBAR_DRM_INVALID_ARGUMENT,
	    "reject an empty native damage list");
	rectangles[0].width = 1;
	check(t1_touchbar_drm_copy_rotated_xrgb8888_rectangles(destination,
	    sizeof(destination), 12, source, sizeof(source), 3, 2,
	    rectangles, 65) == T1_TOUCHBAR_DRM_INVALID_ARGUMENT,
	    "reject more than 64 native damage rectangles");
}

static void test_damage_clip_mapping(void)
{
	struct t1_touchbar_drm_damage_rectangle damage;
	struct t1_touchbar_drm_clip_rectangle clip;

	damage.x = 0;
	damage.y = 0;
	damage.width = 2170;
	damage.height = 60;
	check(t1_touchbar_drm_damage_to_clip(&damage, 2170, 60, &clip) ==
	    T1_TOUCHBAR_DRM_OK, "map full logical damage");
	check(clip.x1 == 0 && clip.y1 == 0 && clip.x2 == 60 &&
	    clip.y2 == 2170, "map the full frame to portrait DRM coordinates");

	damage.width = 1;
	damage.height = 1;
	check(t1_touchbar_drm_damage_to_clip(&damage, 2170, 60, &clip) ==
	    T1_TOUCHBAR_DRM_OK, "map top-left pixel damage");
	check(clip.x1 == 59 && clip.y1 == 0 && clip.x2 == 60 &&
	    clip.y2 == 1, "flip the top-left pixel onto the native short axis");

	damage.x = 2169;
	damage.y = 59;
	check(t1_touchbar_drm_damage_to_clip(&damage, 2170, 60, &clip) ==
	    T1_TOUCHBAR_DRM_OK, "map bottom-right pixel damage");
	check(clip.x1 == 0 && clip.y1 == 2169 && clip.x2 == 1 &&
	    clip.y2 == 2170, "preserve exclusive edges at the display limits");

	damage.x = 100;
	damage.y = 20;
	damage.width = 50;
	damage.height = 10;
	check(t1_touchbar_drm_damage_to_clip(&damage, 2170, 60, &clip) ==
	    T1_TOUCHBAR_DRM_OK, "map an interior rectangle");
	check(clip.x1 == 30 && clip.y1 == 100 && clip.x2 == 40 &&
	    clip.y2 == 150, "use the hardware-proven damage transform");

	damage.width = 0;
	memset(&clip, 0xa5, sizeof(clip));
	check(t1_touchbar_drm_damage_to_clip(&damage, 2170, 60, &clip) ==
	    T1_TOUCHBAR_DRM_INVALID_ARGUMENT, "reject invalid clip damage");
	check(clip.x1 == 0 && clip.y1 == 0 && clip.x2 == 0 && clip.y2 == 0,
	    "clear clip output on rejection");
}

int main(void)
{
	test_card_names();
	test_geometry();
	test_rotation();
	test_partial_rotation();
	test_damage_clip_mapping();
	check(strcmp(t1_touchbar_drm_status_string(T1_TOUCHBAR_DRM_OK),
	    "Touch Bar DRM operation succeeded") == 0,
	    "describe known status");
	check(strcmp(t1_touchbar_drm_status_string(
	    (enum t1_touchbar_drm_status)999),
	    "unknown Touch Bar DRM failure") == 0,
	    "describe unknown status without external detail");

	if (failures != 0) {
		fprintf(stderr, "Touch Bar DRM: %u tests failed\n", failures);
		return 1;
	}
	puts("Touch Bar DRM: all tests passed");
	return 0;
}
