#include <linux/err.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/irqreturn.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/sched.h>
#include "vintage2d.h"
#include "v2d_ioctl.h"

MODULE_LICENSE("GPL");

#define MAX_DEVICE_NUM 255
#define DEVICE_REGION_NAME "vintage_region"
#define DEVICE_CLASS_NAME "vintage_class"
#define DRIVER_NAME "vintage"
#define MMIO_MEMORY_SIZE 4096
#define BAR_MEM 0
#define VINTAGE_CMD_SIZE 4
#define IS_CMD_CORRECT(cmd) (!(cmd & 0x80080002))
#define IS_COLOR_CMD_CORRECT(cmd) (!(cmd & 0xffff0002))

static int vintage_open(struct inode *inode, struct file *file);
static int vintage_release(struct inode *inode, struct file *file);
static ssize_t vintage_write(struct file *filp, const char *buffer, size_t len, loff_t * off);
static long vintage_ioctl(struct file *, unsigned int num, unsigned long param);
static int vintage_mmap(struct file *, struct vm_area_struct *);
static int vintage_fsync(struct file *, loff_t, loff_t, int);

static int vintage_probe(struct pci_dev *dev, const struct pci_device_id *id);
static void vintage_remove(struct pci_dev *dev);

static struct pci_device_id vintage_ids[] = {
        { PCI_DEVICE(VINTAGE2D_VENDOR_ID, VINTAGE2D_DEVICE_ID) },
        { 0 }
};

static dev_t first_device_no;
static struct class * device_class;

static struct file_operations vintage_ops = {
		.owner		= THIS_MODULE,
		.write 		= vintage_write,
		.open 		= vintage_open,
		.release 	= vintage_release,
		.mmap       = vintage_mmap,
		.compat_ioctl = vintage_ioctl,
		.unlocked_ioctl = vintage_ioctl,
		.fsync = vintage_fsync
};

static struct pci_driver vintage_driver = {
		.name 		= DRIVER_NAME,
		.id_table 	= vintage_ids,
		.probe 		= vintage_probe,
		.remove 	= vintage_remove
};

typedef struct device_context device_context_t;

typedef struct {
	dev_t number;
	int minor;
	struct cdev * cdev;
	struct pci_dev * pci_dev;
	void * iomem;
	wait_queue_head_t queue;
	struct mutex mutex;
	device_context_t * current_context;
} device_desc_t;

typedef struct {
	unsigned long * cpu_addr;
	dma_addr_t dma_addr;
} device_page_t;

typedef struct {
	int width;
	int height;
	int pages_count;
	device_page_t page_table;
	device_page_t * pages;
} device_canvas_t;

struct device_context {
	device_desc_t *device_desc;
	device_canvas_t canvas;
	bool ioctl_state;
	long last_fill_color_cmd;
	long last_src_pos_cmd;
	long last_dst_pos_cmd;
};

static device_desc_t device_descriptions[MAX_DEVICE_NUM];

void vintage_reset_device(void *iomem) {
	iowrite32(VINTAGE2D_RESET_DRAW | VINTAGE2D_RESET_FIFO | VINTAGE2D_RESET_TLB,
			  iomem + VINTAGE2D_RESET);
	iowrite32(VINTAGE2D_INTR_NOTIFY | VINTAGE2D_INTR_INVALID_CMD | VINTAGE2D_INTR_PAGE_FAULT |
			  VINTAGE2D_INTR_CANVAS_OVERFLOW | VINTAGE2D_INTR_FIFO_OVERFLOW,
			  iomem + VINTAGE2D_INTR);
	iowrite32(0, iomem + VINTAGE2D_CMD_READ_PTR);
	iowrite32(0, iomem + VINTAGE2D_CMD_WRITE_PTR);
}

void vintage_start_device(void *iomem) {
	vintage_reset_device(iomem);
	iowrite32(VINTAGE2D_INTR_NOTIFY | VINTAGE2D_INTR_INVALID_CMD | VINTAGE2D_INTR_PAGE_FAULT |
			  VINTAGE2D_INTR_CANVAS_OVERFLOW | VINTAGE2D_INTR_FIFO_OVERFLOW,
			  iomem + VINTAGE2D_INTR_ENABLE);
	iowrite32(VINTAGE2D_ENABLE_FETCH_CMD | VINTAGE2D_ENABLE_DRAW,
			  iomem + VINTAGE2D_ENABLE);
}

void vintage_stop_device(void *iomem) {
	iowrite32(0, iomem + VINTAGE2D_ENABLE);
	iowrite32(0, iomem + VINTAGE2D_INTR_ENABLE);
	vintage_reset_device(iomem);
}

void remove_device(device_desc_t * device_desc) {
	if (device_desc->pci_dev != NULL) {
		vintage_stop_device(device_desc->iomem);
		if (pci_is_enabled(device_desc->pci_dev)) {
			pci_disable_device(device_desc->pci_dev);
		}
		pci_clear_master(device_desc->pci_dev);
		free_irq(device_desc->pci_dev->irq, device_desc);
		pci_iounmap(device_desc->pci_dev, device_desc->iomem);
		pci_release_regions(device_desc->pci_dev);
		device_destroy(device_class, device_desc->number);
	}
	if (device_desc->cdev != NULL) {
		cdev_del(device_desc->cdev);
	}
	device_desc->iomem = NULL;
	device_desc->cdev = NULL;
	device_desc->pci_dev = NULL;
	device_desc->current_context = NULL;
}

device_desc_t * find_device_desc(struct pci_dev *dev) {
	int i;
	for(i = 0; i < MAX_DEVICE_NUM; i++) {
		if (device_descriptions[i].pci_dev == NULL) {
			return &device_descriptions[i];
		}
	}
	return NULL;
}

device_desc_t * find_device_desc_by_minor(int minor) {
	int i;
	for(i = 0; i < MAX_DEVICE_NUM; i++) {
		if (device_descriptions[i].minor == minor) {
			return &device_descriptions[i];
		}
	}
	return NULL;
}

int get_data_from_user(void * buffer, void * usr_addr) {
	if (copy_from_user(buffer, usr_addr, VINTAGE_CMD_SIZE) > 0) {
		return -1;
	}
	return 0;
}

int get_fifo_space(device_desc_t * device_desc) {
	return ioread32(device_desc->iomem + VINTAGE2D_FIFO_FREE);
}

void wait_for_fifo_space(device_desc_t * device_desc, int num) {
	wait_event(device_desc->queue, get_fifo_space(device_desc) > num);
}

int get_counter_value(device_desc_t * device_desc) {
	return ioread32(device_desc->iomem + VINTAGE2D_COUNTER);
}

void synchronize_device(device_desc_t * device_desc) {
	long flag, next_flag;

	if (device_desc->current_context == NULL) {
		return;
	}
	flag = get_counter_value(device_desc);
	next_flag = flag == 0 ? 1 : 0;
	wait_for_fifo_space(device_desc, 1);
	iowrite32(VINTAGE2D_CMD_COUNTER(next_flag, 1), device_desc->iomem + VINTAGE2D_FIFO_SEND);
	wait_event(device_desc->queue, get_counter_value(device_desc) == next_flag);
	device_desc->current_context = NULL;
}

void swap_context(device_context_t * new_context) {
	void * iomem;
	iomem = new_context->device_desc->iomem;
	synchronize_device(new_context->device_desc);

	iowrite32(VINTAGE2D_RESET_TLB, iomem + VINTAGE2D_RESET);
	wait_for_fifo_space(new_context->device_desc, 2);
	iowrite32(VINTAGE2D_CMD_CANVAS_PT(new_context->canvas.page_table.dma_addr, 0),
			  iomem + VINTAGE2D_FIFO_SEND);
	iowrite32(VINTAGE2D_CMD_CANVAS_DIMS(new_context->canvas.width, new_context->canvas.height, 1),
			  iomem + VINTAGE2D_FIFO_SEND);
	new_context->device_desc->current_context = new_context;
}

int validate_pos_cmd(long cmd, device_canvas_t * canvas) {
	long x, y;
	x = V2D_CMD_POS_X(cmd);
	y = V2D_CMD_POS_Y(cmd);

	if (!IS_CMD_CORRECT(cmd) || x < 0 || x >= canvas->width ||
		y < 0 || y >= canvas->height) {
		return -1;
	}
	return 0;
}

int vintage_src_pos_cmd(long cmd, device_context_t * context) {
	if (validate_pos_cmd(cmd, &context->canvas) < 0) {
		return -1;
	}
	context->last_src_pos_cmd = VINTAGE2D_CMD_SRC_POS(V2D_CMD_POS_X(cmd),
													  V2D_CMD_POS_Y(cmd), 0);
	return 0;
}

int vintage_dst_post_cmd(int cmd, device_context_t * context) {
	if (validate_pos_cmd(cmd, &context->canvas) < 0) {
		return -1;
	}
	context->last_dst_pos_cmd = VINTAGE2D_CMD_DST_POS(V2D_CMD_POS_X(cmd),
													  V2D_CMD_POS_Y(cmd), 0);
	return 0;
}

int vintage_fill_color_cmd(int cmd, device_context_t * context) {
	if (!IS_COLOR_CMD_CORRECT(cmd)) {
		return -1;
	}
	context->last_fill_color_cmd = VINTAGE2D_CMD_FILL_COLOR(V2D_CMD_COLOR(cmd), 0);
	return 0;
}

int validate_do_blit_cmd(long cmd, device_context_t * context) {
	long src_pos_x, src_pos_y, dst_pos_x, dst_pos_y, width, height;
	if (!IS_CMD_CORRECT(cmd) ||
			context->last_src_pos_cmd == 0 ||
			context->last_dst_pos_cmd == 0) {
		return -1;
	}

	src_pos_x = V2D_CMD_POS_X(context->last_src_pos_cmd);
	src_pos_y = V2D_CMD_POS_Y(context->last_src_pos_cmd);
	dst_pos_x = V2D_CMD_POS_X(context->last_dst_pos_cmd);
	dst_pos_y = V2D_CMD_POS_Y(context->last_dst_pos_cmd);
	width = V2D_CMD_WIDTH(cmd);
	height = V2D_CMD_HEIGHT(cmd);

	if (src_pos_x + width > context->canvas.width ||
			src_pos_y + height > context->canvas.height ||
			dst_pos_x + width > context->canvas.width ||
			dst_pos_y + height > context->canvas.height) {
		return -1;
	}
	return 0;
}

int vintage_do_blit_cmd(int cmd, device_context_t * context) {
	void * iomem;

	if (validate_do_blit_cmd(cmd, context) < 0) {
		return -1;
	}

	iomem = context->device_desc->iomem;

	wait_for_fifo_space(context->device_desc, 3);
	iowrite32(context->last_src_pos_cmd, iomem + VINTAGE2D_FIFO_SEND);
	iowrite32(context->last_dst_pos_cmd, iomem + VINTAGE2D_FIFO_SEND);
	iowrite32(VINTAGE2D_CMD_DO_BLIT(V2D_CMD_WIDTH(cmd), V2D_CMD_HEIGHT(cmd), 0),
			  iomem + VINTAGE2D_FIFO_SEND);

	context->last_src_pos_cmd = 0;
	context->last_dst_pos_cmd = 0;
	return 0;
}

int validate_do_fill_cmd(long cmd, device_context_t * context) {
	long dst_pos_x, dst_pos_y, width, height;

	if (!IS_CMD_CORRECT(cmd) ||
			context->last_fill_color_cmd == 0 ||
			context->last_dst_pos_cmd == 0) {
		return -1;
	}
	dst_pos_x = V2D_CMD_POS_X(context->last_dst_pos_cmd);
	dst_pos_y = V2D_CMD_POS_Y(context->last_dst_pos_cmd);
	width = V2D_CMD_WIDTH(cmd);
	height = V2D_CMD_HEIGHT(cmd);
	if (dst_pos_x + width > context->canvas.width ||
			dst_pos_y + height > context->canvas.height) {
		return -1;
	}
	return 0;
}

int vintage_do_fill_cmd(int cmd, device_context_t * context) {
	void * iomem;

	if (validate_do_fill_cmd(cmd, context) < 0) {
		return -1;
	}

	iomem = context->device_desc->iomem;

	wait_for_fifo_space(context->device_desc, 3);
	iowrite32(context->last_dst_pos_cmd, iomem + VINTAGE2D_FIFO_SEND);
	iowrite32(context->last_fill_color_cmd, iomem + VINTAGE2D_FIFO_SEND);
	iowrite32(VINTAGE2D_CMD_DO_FILL(V2D_CMD_WIDTH(cmd), V2D_CMD_HEIGHT(cmd), 1),
			  iomem + VINTAGE2D_FIFO_SEND);

	context->last_dst_pos_cmd = 0;
	context->last_fill_color_cmd = 0;
	return 0;
}

irqreturn_t irq_handler(int irq_num, void * dev) {
	int intr;
	device_desc_t * device_desc;

	device_desc = (device_desc_t *) dev;

	if (device_desc->pci_dev->irq != irq_num) {
		return IRQ_NONE;
	}

	intr = ioread32(device_desc->iomem + VINTAGE2D_INTR);

	if (intr & VINTAGE2D_INTR_NOTIFY) {
		wake_up(&device_desc->queue);
	}
	if (intr & VINTAGE2D_INTR_INVALID_CMD) {
		printk(KERN_ERR "Unexpected interrupt: invalid command\n");
	}
	if (intr & VINTAGE2D_INTR_PAGE_FAULT) {
		printk(KERN_ERR "Unexpected interrupt: page fault\n");
	}
	if (intr & VINTAGE2D_INTR_CANVAS_OVERFLOW) {
		printk(KERN_ERR "Unexpected interrupt: canvas overflow\n");
	}
	if (intr & VINTAGE2D_INTR_FIFO_OVERFLOW) {
		printk(KERN_ERR "Unexpected interrupt: fifo overflow\n");
	}

	iowrite32(intr, device_desc->iomem + VINTAGE2D_INTR);

	return IRQ_HANDLED;
}

static int vintage_open(struct inode *inode, struct file *file) {
	int minor;
	device_desc_t * device_desc;
	device_context_t * context;

	minor = iminor(inode);
	device_desc = find_device_desc_by_minor(minor);
	if (device_desc == NULL) {
		return -ENODEV;
	}
	context = (device_context_t * ) kzalloc(sizeof(device_context_t), GFP_KERNEL);
	if (!context) {
		return -ENOMEM;
	}
	context->device_desc = device_desc;
	file->private_data = (void *) context;
	return 0;
}

static int vintage_release(struct inode *inode, struct file *file) {
	device_context_t * context;
	device_canvas_t * canvas;
	struct device * device;
	int i;

	context = (device_context_t *) file->private_data;
	canvas = &context->canvas;
	device = &context->device_desc->pci_dev->dev;

	dma_free_coherent(device, VINTAGE2D_PAGE_SIZE, canvas->page_table.cpu_addr,
					  canvas->page_table.dma_addr);
	for (i = 0; i < canvas->pages_count; i++) {
		dma_free_coherent(device, VINTAGE2D_PAGE_SIZE, canvas->pages[i].cpu_addr,
						  canvas->pages[i].dma_addr);
	}
	kfree(file->private_data);
	return 0;
}

static ssize_t vintage_write(struct file * file, const char *usr_addr, size_t len, loff_t * off) {
	int cmd, ret;
	device_context_t * context;

	context = (device_context_t *) file->private_data;

	mutex_lock(&context->device_desc->mutex);

	if (len % VINTAGE_CMD_SIZE != 0) {
		goto write_error;
	}
	if (!context->ioctl_state) {
		goto write_error;
	}
	if (get_data_from_user(&cmd, (void *) usr_addr) < 0) {
		goto write_error;
	}

	if (context->device_desc->current_context != context) {
		swap_context(context);
	}

	switch(V2D_CMD_TYPE(cmd)) {
		case V2D_CMD_TYPE_SRC_POS:
			ret = vintage_src_pos_cmd(cmd, context);
			break;
		case V2D_CMD_TYPE_DST_POS:
			ret = vintage_dst_post_cmd(cmd, context);
			break;
		case V2D_CMD_TYPE_FILL_COLOR:
			ret = vintage_fill_color_cmd(cmd, context);
			break;
		case V2D_CMD_TYPE_DO_BLIT:
			ret = vintage_do_blit_cmd(cmd, context);
			break;
		case V2D_CMD_TYPE_DO_FILL:
			ret = vintage_do_fill_cmd(cmd, context);
			break;
		default:
			goto write_error;
	}

	mutex_unlock(&context->device_desc->mutex);

	if (ret != -1) {
		*off += VINTAGE_CMD_SIZE;
		return VINTAGE_CMD_SIZE;
	} else {
		return -EINVAL;
	}

	write_error:
		mutex_unlock(&context->device_desc->mutex);
		return -EINVAL;
}

int allocate_canvas(device_context_t * context, int width, int height) {
	device_canvas_t * canvas;
	struct device * device;
	int i;
	int pages_count;
	device_page_t * curr_page;
	canvas = &context->canvas;
	device = &context->device_desc->pci_dev->dev;

	canvas->page_table.cpu_addr = dma_alloc_coherent(device, VINTAGE2D_PAGE_SIZE,
													 &canvas->page_table.dma_addr, GFP_KERNEL);
	if (!canvas->page_table.cpu_addr) {
		return -1;
	}
	pages_count = DIV_ROUND_UP((width * height), VINTAGE2D_PAGE_SIZE);
	canvas->pages = (device_page_t *) kzalloc(pages_count * sizeof(device_page_t), GFP_KERNEL);
	if (!canvas->pages) {
		return -1;
	}
	for (i = 0; i < pages_count; i++) {
		curr_page = &canvas->pages[i];
		curr_page->cpu_addr = dma_alloc_coherent(device, VINTAGE2D_PAGE_SIZE,
												 &curr_page->dma_addr, GFP_KERNEL);
		if (!curr_page->cpu_addr) {
			return -1;
		}
		canvas->page_table.cpu_addr[i] = curr_page->dma_addr | VINTAGE2D_PTE_VALID;
	}

	canvas->width = width;
	canvas->height = height;
	canvas->pages_count = pages_count;
	return 0;
}

static long vintage_ioctl(struct file * file, unsigned int cmd, unsigned long usr_addr) {
	struct v2d_ioctl_set_dimensions dimensions;
	device_context_t * context;

	context = (device_context_t *) file->private_data;

	if (cmd != V2D_IOCTL_SET_DIMENSIONS) {
		return -ENOTTY;
	}
	if (context->ioctl_state) {
		return -EINVAL;
	}
	if(get_data_from_user(&dimensions, (void *) usr_addr) < 0) {
		return -EINVAL;
	}
	if (dimensions.width < 1 || dimensions.width > 2048 ||
			dimensions.height < 1 || dimensions.height > 2048) {
		return -EINVAL;
	}
	if (allocate_canvas(context, dimensions.width, dimensions.height) < 0) {
		return -ENOMEM;
	}
	context->ioctl_state = true;

	return 0;
}

static int vintage_mmap(struct file * file, struct vm_area_struct * vma) {
	unsigned long i, mmap_pages;
	device_context_t * context;

	context = (device_context_t *) file->private_data;

	if (!(vma->vm_flags & VM_SHARED)) {
		return -EINVAL;
	}
	if (!context->ioctl_state) {
		return -EINVAL;
	}
	mmap_pages = DIV_ROUND_UP((vma->vm_end - vma->vm_start), VINTAGE2D_PAGE_SIZE);
	if (mmap_pages > context->canvas.pages_count) {
		return -EINVAL;
	}
	for (i = 0; i < mmap_pages; ++i) {
		if (remap_pfn_range(vma, vma->vm_start + (i * VINTAGE2D_PAGE_SIZE),
							__pa(context->canvas.pages[i].cpu_addr) >> VINTAGE2D_PAGE_SHIFT,
							VINTAGE2D_PAGE_SIZE, vma->vm_page_prot)) {
			return -EAGAIN;
		}
	}

	return 0;
}

static int vintage_fsync(struct file * file, loff_t a, loff_t b, int c) {
	device_context_t * context;
	context = (device_context_t *) file->private_data;

	mutex_lock(&context->device_desc->mutex);
	synchronize_device(context->device_desc);
	mutex_unlock(&context->device_desc->mutex);

	return 0;
}

static int vintage_probe(struct pci_dev *dev, const struct pci_device_id * _) {
	struct cdev *cdev;
    device_desc_t * device_desc;
	struct device * device;
	void * iomem;
	int ret;

	device_desc = find_device_desc(NULL); // find empty slot for device
    if (device_desc == NULL) {
		printk(KERN_ERR "Too many devices\n");
        return -ENODEV;
    }

	cdev = cdev_alloc();
	if (IS_ERR_OR_NULL(cdev)) {
		printk(KERN_ERR "Failed to alloc cdev\n");
		return -ENODEV;
	}
	cdev->ops = &vintage_ops;
	cdev->owner = THIS_MODULE;

	ret = cdev_add(cdev, device_desc->number, 1);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to add cdev\n");
		goto clear_char_dev;
	}

	device = device_create(device_class, NULL, device_desc->number,
						   NULL, "v2d%d", device_desc->minor);
	if (IS_ERR_OR_NULL(device)) {
		printk(KERN_ERR "Failed to create device\n");
		ret = -ENODEV;
		goto clear_char_dev;
	}
	if (!(pci_resource_flags(dev, BAR_MEM) & IORESOURCE_MEM)) {
		printk(KERN_ERR "Invalid device region\n");
		ret = -EFAULT;
		goto clear_create_device;
	}

	ret = pci_request_regions(dev, DRIVER_NAME);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to request regions\n");
		goto clear_create_device;
	}

	iomem = pci_iomap(dev, BAR_MEM, MMIO_MEMORY_SIZE);
	if (IS_ERR_OR_NULL(iomem)) {
		printk(KERN_ERR "Failed to map pci region\n");
		ret = -EFAULT;
		goto clear_request_regions;
	}

	ret = request_irq(dev->irq, irq_handler, IRQF_SHARED, DRIVER_NAME, (void *) device_desc);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to request irq\n");
		goto clear_iomap;
	}

	pci_set_master(dev);

	ret = pci_set_dma_mask(dev, DMA_BIT_MASK(32));
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to set dma mask\n");
		goto clear_pci_master;
	}

	ret = pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(32));
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to set consistent dma mask\n");
		goto clear_pci_master;
	}

	ret = pci_enable_device(dev);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to enable device\n");
		goto clear_pci_master;
	}

	device_desc->cdev = cdev;
	device_desc->pci_dev = dev;
	device_desc->iomem = iomem;
	vintage_start_device(device_desc->iomem);

	return 0;

clear_pci_master:
	pci_clear_master(device_desc->pci_dev);
	free_irq(device_desc->pci_dev->irq, device_desc);
clear_iomap:
	pci_iounmap(device_desc->pci_dev, device_desc->iomem);
clear_request_regions:
	pci_release_regions(device_desc->pci_dev);
clear_create_device:
	device_destroy(device_class, device_desc->number);
clear_char_dev:
	cdev_del(device_desc->cdev);
	return ret;
}

static void vintage_remove(struct pci_dev *dev) {
    device_desc_t * device_desc;

	device_desc = find_device_desc(dev);
    if (device_desc != NULL) {
		remove_device(device_desc);
	}
}

static int vintage_init_module(void) {
    int i, minor, ret;

	ret = alloc_chrdev_region(&first_device_no, 0, MAX_DEVICE_NUM, DEVICE_REGION_NAME);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to alloc chrdev\n");
		return ret;
	}

	device_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME);
	if (IS_ERR_OR_NULL(device_class)) {
		printk(KERN_ERR "Failed to create device class\n");
		unregister_chrdev_region(first_device_no, MAX_DEVICE_NUM);
		return -ENODEV;
	}

	minor = MINOR(first_device_no);
	for(i = 0; i < MAX_DEVICE_NUM; i++) {
        device_descriptions[i].number = MKDEV(MAJOR(first_device_no), minor);
		device_descriptions[i].pci_dev = NULL;
		device_descriptions[i].cdev    = NULL;
		device_descriptions[i].iomem = NULL;
		device_descriptions[i].current_context = NULL;
		device_descriptions[i].minor = minor;
		init_waitqueue_head(&device_descriptions[i].queue);
		mutex_init(&device_descriptions[i].mutex);
		minor++;
    }

	ret = pci_register_driver(&vintage_driver);
	if (IS_ERR_VALUE(ret)) {
		printk(KERN_ERR "Failed to register pci driver\n");
		class_destroy(device_class);
		unregister_chrdev_region(first_device_no, MAX_DEVICE_NUM);
		return ret;
	}

	return 0;
}

static void vintage_exit_module(void) {
	int i;

	pci_unregister_driver(&vintage_driver);
    for(i = 0; i < MAX_DEVICE_NUM; i++) {
		if (device_descriptions[i].pci_dev != NULL) {
			remove_device(&device_descriptions[i]);
		}
	}
	class_destroy(device_class);
	unregister_chrdev_region(first_device_no, MAX_DEVICE_NUM);
}

module_init(vintage_init_module);
module_exit(vintage_exit_module);