/*
 * hello.c
 *
 *  Created on: Nov 3, 2016
 *      Author: MateuszMidor
 */

#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mateusz Midor");
MODULE_DESCRIPTION("A Simple Hello World module");
MODULE_VERSION("0.1");

static char *name = "world"; // An example LKM argument -- default value is "world"
module_param( name, charp, S_IRUGO);// Param desc. charp = char ptr, S_IRUGO can be read/not changed
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");	// parameter description

static int __init hello_init(void) {
	printk(KERN_INFO "Hello %s!\n", name);
	return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void) {
	printk(KERN_INFO "Cleaning up hello module.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
