/**
 * message_queue.c
 *
 *  Created on: Apr 20, 2017
 *      Author: Mateusz Midor
 */

#include <linux/init.h>             // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>           // Core header for loading LKMs into the kernel
#include <linux/device.h>           // Header to support the kernel Driver Model
#include <linux/kernel.h>           // Contains types, macros, functions for the kernel
#include <linux/fs.h>               // Header for the Linux file system support
#include <linux/slab.h>             // kmalloc
#include <linux/completion.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>            // Required for the copy to user function

MODULE_LICENSE("GPL");              // The license type -- this affects available functionality
MODULE_AUTHOR("Mateusz Midor");     // The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux IPC message queue"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

#define  DEVICE_NAME "message_queue"    // The device will appear at /dev/char_dev_example using this value
#define  CLASS_NAME  "message_queue"    // The device class -- this is a character device driver

static int majorNumber;                 // Major number for the device; to be assigned dynamically
static struct class* _class = NULL;     // The device-driver class struct pointer
static struct device* _device = NULL;   // The device-driver device struct pointer

// Device operation forward declarations
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

// File operations of device
static struct file_operations fops = {
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

bool read_done = false; // after message has been read this is set to true so next read returns length 0 - end of data

// define message queue itself
LIST_HEAD(message_queue);
struct message {
    struct list_head list;
    char data[256];
};

// message counter and limit
size_t message_count = 0;
#define MAX_MESSAGE_COUNT 5

// for blocking user space program when writing to full queue or reading from empty queue
static DECLARE_COMPLETION(queue_not_empty);
static DECLARE_COMPLETION(queue_not_full);

// for synchronizim message_queue access
static DEFINE_MUTEX(message_queue_mutex);

/**
 * @brief   Register /dev/message_queue character device
 */
static int register_message_queue_dev(void) {
    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0) {
        printk(KERN_ALERT "message_queue failed to register a major number\n");
        return majorNumber;
    }
    printk(
    KERN_INFO "message_queue: registered correctly with major number %d\n", majorNumber);

    // Register the device class
    _class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(_class)) {            // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(_class);   // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "message_queue: device class registered correctly\n");

    // Register the device driver
    _device = device_create(_class, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(_device)) {               // Clean up if there is an error
        class_destroy(_class); // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(_device);
    }
    printk(KERN_INFO "message_queue: device class created correctly\n"); // Made it! device was initialized
    return 0;
}

/**
 * @brief   Unregister /dev/message_queue character device
 */
static void unregister_message_queue_dev(void) {
    device_destroy(_class, MKDEV(majorNumber, 0));      // remove the device
    class_unregister(_class);                           // unregister the device class
    class_destroy(_class);                              // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);        // unregister the major number
}

/**
 * @brief   Release message queue memory back to the kernel
 */
static void clean_message_queue(void) {
    struct message *entry;

    while (!list_empty(&message_queue)) {
        entry = list_first_entry(&message_queue, struct message, list);
        printk(KERN_INFO "freeing %s", entry->data);
        list_del(&entry->list);
        kfree(entry);
    }
}

///**
// * @brief   Print all messages held in the queue
// */
//static void print_message_queue(void) {
//    struct message *entry;
//
//    list_for_each_entry(entry, &message_queue, list)
//        printk(KERN_INFO "%s", entry->data);
//}

/**
 * @brief   Kernel module init function.
 * @return  0 on success
 */
static int __init message_queue_init(void) {
    printk(KERN_INFO "message_queue: init\n");
    queue_not_full.done = MAX_MESSAGE_COUNT; // can write this number of messages
    return register_message_queue_dev();
}

/**
 * @brief   Kernel module exit function
 */
static void __exit message_queue_exit(void) {
    clean_message_queue();
    unregister_message_queue_dev();
    printk(KERN_INFO "message_queue: exit\n");
}

/**
 * @brief   User opens /dev/message_queue
 * @return  0 on success
 */
static int dev_open(struct inode *inodep, struct file *filep) {
    return 0;
}

/**
 * @brief   User reads single message from the queue
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    struct message *entry;
    size_t datasize;
    int characters_left = 0;


    // if read is done, return 0 (meaning end of message data)
    if (read_done) {
        read_done = false; // prepare for next message read
        return 0;
    }

    // block till there is some message on the queue
    if (wait_for_completion_interruptible(&queue_not_empty) == -ERESTARTSYS)
        return -ERESTARTSYS;

    mutex_lock(&message_queue_mutex);

    entry = list_first_entry(&message_queue, struct message, list);
    datasize = strlen(entry->data);

    // write message data to the userspace buffer
    characters_left = copy_to_user(buffer, entry->data, datasize);

    list_del(&entry->list);
    kfree(entry);
    read_done = true;
    message_count--;
    printk(KERN_INFO "message_queue: messages left: %u\n", (unsigned)message_count);
    complete(&queue_not_full);
    mutex_unlock(&message_queue_mutex);

    return datasize;
}

/**
 * @brief   User writes single message to the queue
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    struct message *msg;

    // block till there is some space on the queue
    if (wait_for_completion_interruptible(&queue_not_full) == -ERESTARTSYS)
        return -ERESTARTSYS;

    // alloc new message from kernel memory
    msg = kmalloc(sizeof(struct message), GFP_KERNEL);
    if (!msg) {
        printk(KERN_ERR "message_queue: kmalloc failed\n");
        return -ENOMEM;
    }

    // enforce message size limit
    len = min(len, sizeof(msg->data) -1); // -1 for \0

    // fill message data from buffer
    strncpy(msg->data, buffer, len);

    // ensure message is null terminated
    msg->data[len] = '\0';

    mutex_lock(&message_queue_mutex);
    list_add_tail(&msg->list, &message_queue); // put message on the list
    message_count++;
    complete(&queue_not_empty);
    mutex_unlock(&message_queue_mutex);

    printk(KERN_INFO "message_queue: messages available: %u\n", (unsigned)message_count);

    return len;
}

/**
 * @brief   User closes /dev/message_queue
 * @return  0 on success
 */
static int dev_release(struct inode *inodep, struct file *filep) {
    return 0;
}

module_init(message_queue_init);
module_exit(message_queue_exit);
