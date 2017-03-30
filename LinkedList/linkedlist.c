/**
 * @file    hello.c
 * @author  Derek Molloy, modified Mateusz Midor
 * @date    4 April 2015, Nov 3, 2016
 * @version 0.1
 * @brief  An introductory "Hello World!" loadable kernel module (LKM) that can display a message
 * in the /var/log/kern.log file when the module is loaded and removed. The module can accept an
 * argument when it is loaded -- the name, which appears in the kernel log files.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
*/

#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/list.h>



// define and init list head
LIST_HEAD(country_capital_list);

// define list element type
struct country_capital {
    struct list_head list; // this makes country_capital valid linked-list element
    char *country;
    char *capital;
};

// define some list elements
struct country_capital c1 = {
    .country = "hiszpania",
    .capital = "madryt"
};

struct country_capital c2 = {
    .country = "wietnam",
    .capital = "phnompen"
};

struct country_capital c3 = {
    .country = "peru",
    .capital = "lima"
};


// add elments to the list
static void fill_list(void) {
    list_add_tail(&c1.list, &country_capital_list);
    list_add_tail(&c2.list, &country_capital_list);
    list_add_tail(&c3.list, &country_capital_list);
}

// print list elements
static void print_list(void) {
    struct country_capital *entry;

    list_for_each_entry(entry, &country_capital_list, list)
        printk(KERN_INFO "%s - %s\n", entry->country, entry->capital);
}

// #######################################################################
// HERE STARTS THE STANDARD MODULE CONFIG - SETUP - TEARDOWN
// #######################################################################

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mateusz Midor");
MODULE_DESCRIPTION("A linux linked list example");
MODULE_VERSION("0.1");

static int __init hello_init(void) {
    printk(KERN_INFO "Preparing linkedlist module.\n");
    fill_list();
    print_list();
	return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void) {
	printk(KERN_INFO "Cleaning up linkedlist module.\n\n");
}


module_init(hello_init);
module_exit(hello_cleanup);
