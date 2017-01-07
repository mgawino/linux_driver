#ifndef V2D_IOCTL_H
#define V2D_IOCTL_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdint.h>
#endif

#include <linux/ioctl.h>

struct v2d_ioctl_set_dimensions {
	uint16_t height;
	uint16_t width;
};
#define V2D_IOCTL_SET_DIMENSIONS _IOW('2', 0x00, struct v2d_ioctl_set_dimensions)

/* Commands */

#define V2D_CMD_TYPE(cmd)		((cmd) & 0xff)
#define V2D_CMD_TYPE_SRC_POS		0x08
#define V2D_CMD_TYPE_DST_POS		0x0c
#define V2D_CMD_TYPE_FILL_COLOR		0x10
#define V2D_CMD_TYPE_DO_BLIT		0x14
#define V2D_CMD_TYPE_DO_FILL		0x18

#define V2D_CMD_SRC_POS(x, y)		(V2D_CMD_TYPE_SRC_POS | (x) << 8 | (y) << 20)
#define V2D_CMD_DST_POS(x, y)		(V2D_CMD_TYPE_DST_POS | (x) << 8 | (y) << 20)
#define V2D_CMD_FILL_COLOR(c)		(V2D_CMD_TYPE_FILL_COLOR | (c) << 8)
#define V2D_CMD_DO_BLIT(w, h)		(V2D_CMD_TYPE_DO_BLIT | ((w) - 1) << 8 | ((h) - 1) << 20)
#define V2D_CMD_DO_FILL(w, h)		(V2D_CMD_TYPE_DO_FILL | ((w) - 1) << 8 | ((h) - 1) << 20)

#define V2D_CMD_POS_X(cmd)		((cmd) >> 8 & 0x7ff)
#define V2D_CMD_POS_Y(cmd)		((cmd) >> 20 & 0x7ff)
#define V2D_CMD_WIDTH(cmd)		(((cmd) >> 8 & 0x7ff) + 1)
#define V2D_CMD_HEIGHT(cmd)		(((cmd) >> 20 & 0x7ff) + 1)
#define V2D_CMD_COLOR(cmd)		((cmd) >> 8 & 0xff)

#endif
