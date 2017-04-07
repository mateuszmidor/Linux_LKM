/**
 * firewall.c
 *
 *   @date: Apr 04, 2017
 * @author: Mateusz Midor
 *   @note: This is based on http://www.roman10.net/2011/07/23/how-to-filter-network-packets-using-netfilterpart-2-implement-the-hook-function/
 */
#include "common.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>

#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Liu Feipeng/roman10, modified by Mateusz Midor");

// single firewall rule as received from the user
//struct user_friendly_firewall_rule {
//	packet_direction in_out;
//	char *src_ip;
//	char *src_netmask;
//	char *src_port;
//	char *dest_ip;
//	char *dest_netmask;
//	char *dest_port;
//	protocol_type proto;
//	action_type action;
//};

// single firewall rule as stored in the rule list
struct kernel_firewall_rule {
	firewall_rule rule;
	struct list_head list;
};

// define the policy list head
static struct kernel_firewall_rule policy_list;
static unsigned int rule_count = 0;

//the structure used to register the filtering function for incoming and outgoing packets
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static bool reading_done = false;


int static sprintf_rule(char *buff, unsigned int index, firewall_rule *rule) {

	// direction, action and protocol to string
	const char *dir = rule->in_out == DIRECTION_NONE ? "NONE" : rule->in_out == DIRECTION_INCOMING ? "IN" : "OUT";
	const char *action = rule->action == ACTION_BLOCK ? "block" : "unblock";
	const char *protocol = rule->proto == PROTOCOL_ALL ? "TCP/UDP" : rule->proto == PROTOCOL_TCP ? "TCP" : "UDP";

	// src and dst ip to string
	char src_ip[16] = {'\0'};
	char dst_ip[16] = {'\0'};
	unsigned char ip_array[4];
	memcpy(&ip_array, &rule->src_ip, sizeof(ip_array));
	sprintf(src_ip, "%u.%u.%u.%u", ip_array[3], ip_array[2], ip_array[1], ip_array[0]);
	memcpy(&ip_array, &rule->dest_ip, sizeof(ip_array));
	sprintf(dst_ip, "%u.%u.%u.%u", ip_array[3], ip_array[2], ip_array[1], ip_array[0]);

	// build final rule string
	return sprintf(buff, "%u. dir %s, protocol %s, src ip %s, src port %u, dst ip %s, dst port %d, action %s\n",
			index, dir, protocol, src_ip, rule->src_port, dst_ip, rule->dest_port, action);
}

/**
 * @brief	Convert port number string to integer
 */
unsigned int port_str_to_int(char *port_str) {
	unsigned int port = 0;
	int i = 0;
	if (port_str == NULL) {
		return 0;
	}
	while (port_str[i] != '\0') {
		port = port * 10 + (port_str[i] - '0');
		++i;
	}
	return port;
}

/**
 * @brief 	Compare the two IP addresses, only the masked part
 */
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
	unsigned int tmp = ntohl(ip);    //network to host long
	int cmp_len = 32;
	int i = 0, j = 0;
	printk(KERN_INFO "compare ip: %u <=> %u\n", tmp, ip_rule);
	if (mask != 0) {
		//printk(KERN_INFO "deal with mask\n");
		//printk(KERN_INFO "mask: %d.%d.%d.%d\n", mask[0], mask[1], mask[2], mask[3]);
		cmp_len = 0;
		for (i = 0; i < 32; ++i) {
			if (mask & (1 << (32 - 1 - i)))
				cmp_len++;
			else
				break;
		}
	}
	/*compare the two IP addresses for the first cmp_len bits*/
	for (i = 31, j = 0; j < cmp_len; --i, ++j) {
		if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
			printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32 - i));
			return false;
		}
	}
	return true;
}

/**
 * @brief	This function filters outgoing packets
 */
unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	/*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct list_head *p;
	struct kernel_firewall_rule *entry;
	firewall_rule *a_rule;
	int i = 0;

	/**get src and dest ip addresses**/
	unsigned int src_ip = (unsigned int) ip_header->saddr;
	unsigned int dest_ip = (unsigned int) ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;

	/***get src and dest port number***/
	if (ip_header->protocol == PROTOCOL_UDP) {
		udp_header = (struct udphdr *) skb_transport_header(skb);
		src_port = (unsigned int) ntohs(udp_header->source);
		dest_port = (unsigned int) ntohs(udp_header->dest);
	} else if (ip_header->protocol == PROTOCOL_TCP) {
		tcp_header = (struct tcphdr *) skb_transport_header(skb);
		src_port = (unsigned int) ntohs(tcp_header->source);
		dest_port = (unsigned int) ntohs(tcp_header->dest);
	}

	printk(
			KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n",
			src_ip, src_port, dest_ip, dest_port, ip_header->protocol);

	//go through the firewall list and check if there is a match
	//in case there are multiple matches, take the first one
	list_for_each(p, &policy_list.list)
	{
		i++;
		entry = list_entry(p, struct kernel_firewall_rule, list);
		a_rule = &entry->rule;
		printk(
				KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n",
				i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask,
				a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask,
				a_rule->dest_port, a_rule->proto, a_rule->action);

		//if a rule doesn't specify as "out", skip it
		if (a_rule->in_out != DIRECTION_OUTGOING) {
			printk(
					KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n",
					i, a_rule->in_out);
			continue;
		} else {
			//check the protocol
			if ((a_rule->proto == PROTOCOL_TCP) && (ip_header->protocol != PROTOCOL_TCP)) {
				printk(
						KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n",
						i);
				continue;
			} else if ((a_rule->proto == PROTOCOL_UDP) && (ip_header->protocol != PROTOCOL_UDP)) {
				printk(
						KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n",
						i);
				continue;
			}

			//check the ip address
			if (a_rule->src_ip == 0) {
				//rule doesn't specify ip: match
			} else {
				if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
					printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
					continue;
				}
			}
			if (a_rule->dest_ip == 0) {
				//rule doesn't specify ip: match
			} else {
				if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
					printk(KERN_INFO "rule %d not match: dest ip mismatch\n",
							i);
					continue;
				}
			}
			//check the port number
			if (a_rule->src_port == 0) {
				//rule doesn't specify src port: match
			} else if (src_port != a_rule->src_port) {
				printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
				continue;
			}
			if (a_rule->dest_port == 0) {
				//rule doens't specify dest port: match
			} else if (dest_port != a_rule->dest_port) {
				printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
				continue;
			}

			//a match is found: take action
			if (a_rule->action == ACTION_BLOCK) {
				printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			} else {
				printk(KERN_INFO "a match is found: %d, accept the packet\n",
						i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_ACCEPT;
			}
		}
	}
	printk(KERN_INFO "no matching is found, accept the packet\n");
	printk(KERN_INFO "---------------------------------------\n");
	return NF_ACCEPT;
}


/**
 * @brief	This function filters incoming packets
 */
unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	/*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct list_head *p;
	struct kernel_firewall_rule *entry;
	firewall_rule *a_rule;
	int i = 0;
	/**get src and dest ip addresses**/
	unsigned int src_ip = (unsigned int) ip_header->saddr;
	unsigned int dest_ip = (unsigned int) ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;
	/***get src and dest port number***/
	if (ip_header->protocol == PROTOCOL_UDP) {
		udp_header = (struct udphdr *) (skb_transport_header(skb) + 20);
		src_port = (unsigned int) ntohs(udp_header->source);
		dest_port = (unsigned int) ntohs(udp_header->dest);
	} else if (ip_header->protocol == PROTOCOL_TCP) {
		tcp_header = (struct tcphdr *) (skb_transport_header(skb) + 20);
		src_port = (unsigned int) ntohs(tcp_header->source);
		dest_port = (unsigned int) ntohs(tcp_header->dest);
	}
	printk(
			KERN_INFO "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n",
			src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
	//go through the firewall list and check if there is a match
	//in case there are multiple matches, take the first one
	list_for_each(p, &policy_list.list)
	{
		i++;
		entry = list_entry(p, struct kernel_firewall_rule, list);
		a_rule = &entry->rule;
		printk(
				KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n",
				i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask,
				a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask,
				a_rule->dest_port, a_rule->proto, a_rule->action);
		//if a rule doesn't specify as "in", skip it
		if (a_rule->in_out != DIRECTION_INCOMING) {
			printk(
					KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n",
					i, a_rule->in_out);
			continue;
		} else {
			//check the protocol
			if ((a_rule->proto == PROTOCOL_TCP) && (ip_header->protocol != PROTOCOL_TCP)) {
				printk(
						KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n",
						i);
				continue;
			} else if ((a_rule->proto == PROTOCOL_UDP) && (ip_header->protocol != PROTOCOL_UDP)) {
				printk(
						KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n",
						i);
				continue;
			}
			//check the ip address
			if (a_rule->src_ip == 0) {
				//
			} else {
				if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
					printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
					continue;
				}
			}
			if (a_rule->dest_ip == 0) {
				//
			} else {
				if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
					printk(KERN_INFO "rule %d not match: dest ip mismatch\n",
							i);
					continue;
				}
			}
			//check the port number
			if (a_rule->src_port == 0) {
				//rule doesn't specify src port: match
			} else if (src_port != a_rule->src_port) {
				printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
				continue;
			}
			if (a_rule->dest_port == 0) {
				//rule doens't specify dest port: match
			} else if (dest_port != a_rule->dest_port) {
				printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
				continue;
			}
			//a match is found: take action
			if (a_rule->action == ACTION_BLOCK) {
				printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			} else {
				printk(KERN_INFO "a match is found: %d, accept the packet\n",
						i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_ACCEPT;
			}
		}
	}
	printk(KERN_INFO "no matching is found, accept the packet\n");
	printk(KERN_INFO "---------------------------------------\n");
	return NF_ACCEPT;
}

/**
 * @brief	Add new filtering rule to the firewall rule list
 */
void add_rule(firewall_rule* user_rule) {
	char buff[256];

	struct kernel_firewall_rule* new_rule;
	new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (new_rule == NULL) {
		printk(KERN_INFO "error: cannot allocate memory for new_rule\n");
		return;
	}

	memcpy(&new_rule->rule, user_rule, sizeof(firewall_rule));

	rule_count++;
	sprintf_rule(buff, rule_count, &new_rule->rule);
	printk(KERN_INFO "add_a_rule %s", buff );

	INIT_LIST_HEAD(&(new_rule->list));
	list_add_tail(&(new_rule->list), &(policy_list.list));
}

/**
 * @brief	Delete rule of given index in the list
 */
void delete_rule(int num) {
	int i = 0;
	struct list_head *p, *q;
	struct kernel_firewall_rule *a_rule;
	printk(KERN_INFO "delete a rule: %d\n", num);
	list_for_each_safe(p, q, &policy_list.list) {
		++i;
		if (i == num) {
			a_rule = list_entry(p, struct kernel_firewall_rule, list);
			list_del(p);
			kfree(a_rule);
			rule_count--;
			return;
		}
	}
}

/**
 * @brief	Add an example rule
 */
void add_a_test_rule(void) {
	firewall_rule rule;

	if (deserialize_rule("tcp out block 10.0.2.15 255.255.255.255 0 anyip anyip 0", &rule))
		add_rule(&rule);
	else
		printk(KERN_INFO "add_a_test_rule - deserialize_rule failed");
}


/**
 * @brief	Forbid SSH connections
 */
void add_nossh_rule(void) {
	firewall_rule rule;

	if (deserialize_rule("tcp out block anyip anyip 0 anyip anyip 22", &rule))
		add_rule(&rule);
	else
		printk(KERN_INFO "add_nossh_rule - deserialize_rule failed");
}

// communication from user space
static int firewall_open(struct inode *node, struct file *f) {
	reading_done = false; // can read
	return 0;
}

static int firewall_release(struct inode *node, struct file *f) {
	return 0;
}

/**
 * @brief	Read firewall rules at /proc/firewall
 */
static ssize_t firewall_read(struct file *f, char __user *user_buff, size_t size, loff_t *offset) {
	struct kernel_firewall_rule *entry;
	char kernel_buff[256];
	int rule_index = 1;
	int written_count = 0;
	int total_written_count = 0;

	if (reading_done)
		return 0; // 0 bytes left for reading

	list_for_each_entry(entry, &policy_list.list, list) {
		written_count = sprintf_rule(kernel_buff, rule_index, &entry->rule);
		copy_to_user(user_buff + total_written_count, kernel_buff, written_count);
		total_written_count += written_count;
		rule_index++;
	}

	reading_done = true;
	return total_written_count; // return number of bytes we put in the file for reading
}

/**
 * @brief	Configure firewall rules at /proc/firewall
 */
static ssize_t firewall_write(struct file *f, const char __user *user_buff, size_t size, loff_t *offset) {
	#define CHECK_OP(op1, op2) ((strcmp(op1, op2) == 0))

	char kernel_buff[256] = {'\0'};
	char operation[15] = {'\0'};
	firewall_rule rule;
	unsigned int rule_index;


	if (size > sizeof(kernel_buff) -1)
		size = sizeof(kernel_buff) -1; // -1 for null terminator

	copy_from_user(kernel_buff, user_buff, size);
	sscanf(kernel_buff, "%s", operation);

	if (CHECK_OP(operation, "add")) {
		if (deserialize_rule(kernel_buff + 4, &rule)) // +4 to skip "add "
			add_rule(&rule);
		else
			printk(KERN_INFO "Add rule failed: invalid rule string\n");
	}
	else if (CHECK_OP(operation, "del")) {
		sscanf(kernel_buff + 4, "%u", &rule_index);	// +4 to skip "add "
		printk(KERN_INFO "Delete rule %u\n", rule_index);
		delete_rule(rule_index);
	}
	else
		printk(KERN_INFO "Unknown operation %s\n", kernel_buff);


	return size; // return number of bytes we taken from file
}

static struct file_operations firewall_proc_ops = {
	.owner   = THIS_MODULE,
	.open    = firewall_open,
	.read    = firewall_read,
	.write	 = firewall_write,
	.release = firewall_release,
};

static void firewall_create_procentry(void) {
	if (proc_create_data(PROCFS_FILENAME, 0666, NULL, &firewall_proc_ops, NULL))
		printk(KERN_INFO "created /proc/%s\n", PROCFS_FILENAME);
}

static void firewall_remove_procentry(void) {
	remove_proc_entry(PROCFS_FILENAME, NULL);
	printk(KERN_INFO "removed /proc/%s\n", PROCFS_FILENAME);
}

/* Initialization routine */
static int __init  init_firewall_module(void) {
	printk(KERN_INFO "initialize kernel module\n");
	firewall_create_procentry();

	INIT_LIST_HEAD(&(policy_list.list));

	/* Fill in the hook structure for incoming packet hook*/
	nfho_in.hook = hook_func_in;
	nfho_in.hooknum = NF_INET_LOCAL_IN;
	nfho_in.pf = PF_INET;
	nfho_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_in);         // Register the hook

	/* Fill in the hook structure for outgoing packet hook*/
	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);    // Register the hook

//	/*this part of code is for testing purpose*/
	add_nossh_rule();
	add_a_test_rule();
	return 0;
}

/* Cleanup routine */
static void __exit cleanup_firewall_module(void) {
	struct list_head *p, *q;
	struct kernel_firewall_rule *a_rule;

	nf_unregister_hook(&nfho_in);
	nf_unregister_hook(&nfho_out);

	printk(KERN_INFO "free policy list\n");
	list_for_each_safe(p, q, &policy_list.list)
	{
		printk(KERN_INFO "free one\n");
		a_rule = list_entry(p, struct kernel_firewall_rule, list);
		list_del(p);
		kfree(a_rule);
	}

	firewall_remove_procentry();
	printk(KERN_INFO "kernel module unloaded.\n");
}

module_init(init_firewall_module);
module_exit(cleanup_firewall_module);
