/*
 * common.h
 *
 *  Created on: Apr 7, 2017
 *      Author: mateusz
 */

#ifndef COMMON_H_
#define COMMON_H_

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/string.h>
#else
#include <string.h>
#endif


// firewall module communication file is /proc/firewall
#define PROCFS_FILENAME "firewall"
#define	ANY_IP "anyip"

// enums related to firwall_rule
typedef enum {PROTOCOL_ALL = 0, PROTOCOL_TCP = 6, PROTOCOL_UDP = 17} protocol_type;
typedef enum {ACTION_BLOCK = 0, ACTION_UNBLOCK = 1} action_type;
typedef enum {DIRECTION_NONE = 0, DIRECTION_INCOMING = 1, DIRECTION_OUTGOING = 2} packet_direction;
typedef enum {ADD_RULE = 0, DELETE_RULE = 1} firewall_operation;


// firewall rule to match against a network packet and decide what to with this packet
typedef struct {
	packet_direction in_out;
	unsigned int src_ip;
	unsigned int src_netmask;
	unsigned int src_port;
	unsigned int dest_ip;
	unsigned int dest_netmask;
	unsigned int dest_port;
	protocol_type proto;
	action_type action;
} firewall_rule;

/**
 * @brief	Convert ip string to ip number
 */
unsigned int ip_str_to_hl(char *ip_str) {
	/*convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]*/
	unsigned char ip_array[4];
	int i = 0;
	unsigned int ip = 0;

	// no ip
	if (ip_str == NULL) {
		return 0;
	}

	// no ip
	if (strcmp(ip_str, ANY_IP) == 0)
		return 0;

	memset(ip_array, 0, 4);
	while (ip_str[i] != '.') {
		ip_array[0] = ip_array[0] * 10 + (ip_str[i++] - '0');
	}
	++i;
	while (ip_str[i] != '.') {
		ip_array[1] = ip_array[1] * 10 + (ip_str[i++] - '0');
	}
	++i;
	while (ip_str[i] != '.') {
		ip_array[2] = ip_array[2] * 10 + (ip_str[i++] - '0');
	}
	++i;
	while (ip_str[i] != '\0') {
		ip_array[3] = ip_array[3] * 10 + (ip_str[i++] - '0');
	}

	/*convert from byte array to host long integer format*/
	ip = (ip_array[0] << 24);
	ip = (ip | (ip_array[1] << 16));
	ip = (ip | (ip_array[2] << 8));
	ip = (ip | ip_array[3]);
	//printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
	return ip;
}

/**
 * @brief 	Deserialize a rule from given string
 * @param	rule_string "protocol direction action srcip srcmask srcport dstip dstmask dstport"
 * @return	True o successful deserialization, False otherwise
 */
bool deserialize_rule(char* rule_string, firewall_rule *out_rule) {

	char protocol[15] = {'\0'};		// tcp/udp/all
	char direction[15] = {'\0'};	// in/out
	char action[15] = {'\0'};		// block/unblock

	char src_ip[15] = {'\0'};
	char src_mask[15] = {'\0'};
	unsigned int src_port;

	char dst_ip[15] = {'\0'};
	char dst_mask[15] = {'\0'};
	unsigned int dst_port;
	int num_retrieved;

	// check for null rule string
	if (!rule_string)
		return false;

	num_retrieved = sscanf(rule_string, "%s %s %s %s %s %u %s %s %u",
							protocol, direction, action, src_ip, src_mask, &src_port, dst_ip, dst_mask, &dst_port);

	// check all arguments were retrieved from rule string
	if (num_retrieved < 9)
		return false;

	#define CHECK_OP(op1, op2) ((strcmp(op1, op2) == 0))
	out_rule->proto = CHECK_OP(protocol, "tcp") ? PROTOCOL_TCP : CHECK_OP(protocol, "ucp") ? PROTOCOL_UDP : PROTOCOL_ALL;
	out_rule->in_out = CHECK_OP(direction, "in") ? DIRECTION_INCOMING : CHECK_OP(direction, "out") ? DIRECTION_OUTGOING : DIRECTION_NONE;
	out_rule->action = CHECK_OP(action, "block") ? ACTION_BLOCK : ACTION_UNBLOCK;
	out_rule->src_ip = ip_str_to_hl(src_ip);
	out_rule->src_netmask = ip_str_to_hl(src_mask);
	out_rule->src_port = src_port;
	out_rule->dest_ip = ip_str_to_hl(dst_ip);
	out_rule->dest_netmask = ip_str_to_hl(dst_mask);
	out_rule->dest_port = dst_port;

	return true;
}

#endif /* COMMON_H_ */
