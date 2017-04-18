/*
 * client.cpp
 *
 *  Created on: Apr 7, 2017
 *      Author: mateusz
 */

#include "common.h"
#include <fstream>
#include <iostream>
#include <algorithm>

using namespace std;

/**
 * @name	cut_token
 * @brief	Cut and return single token from src string (tokens are separated by spaces)
 */
string cut_token(string &src) {
	char head[25] = {'\0'};
	char tail[100] = {'\0'};

	sscanf(src.c_str(), "%s %[^\n]%*c", head, tail);
	src = tail;
	return head;
}

/**
 * @name	get_module_stream
 * @brief	Open and return a read-write file stream to firewall communication file
 */
fstream get_module_stream() {
	const string COMMUNICATION_FILEPATH = "/proc/" PROCFS_FILENAME;
	fstream stream(COMMUNICATION_FILEPATH);

	if (!stream)
		cout << "firewall module not running; communication file doesnt exists: " << COMMUNICATION_FILEPATH << endl;

	return stream;
}

/**
 * @name	print_firewall_rules
 * @brief	Print all currently active firewall rules to stdout
 */
void print_firewall_rules() {
	if (fstream stream = get_module_stream())
		if (stream.peek() != std::ifstream::traits_type::eof())
			cout << stream.rdbuf();
		else
			cout << "[no rules]" << endl;
}

/**
 * @name	add_firewall_rule
 * @brief	Add fireall rule encoded as string to the firewall rule list
 */
void add_firewall_rule(const string &rule_string) {
	firewall_rule tmp;
	if (!deserialize_rule(rule_string.c_str(), &tmp)) {
		cout << "Firewall rule misformatted: " << rule_string << endl;
		return;
	}

	if (fstream stream = get_module_stream())
		stream << "add " << rule_string;
}

/**
 * @name	del_firewall_rule
 * @brief	Delete firewall rule of given number given in rule_number_string
 */
void del_firewall_rule(const string &rule_number_string) {
	unsigned int rule_number;
	if (sscanf(rule_number_string.c_str(), "%u", &rule_number) != 1) {
		cout << "Rule number misformatted: " << rule_number_string << endl;
		return;
	}

	if (fstream stream = get_module_stream())
		stream << "del " << rule_number;
}

/**
 * @name	print_help
 * @brief	Print available commands to stdout
 */
void print_help() {
	cout << "Example commands:\n";
	cout << "\texit\n";
	cout << "\tprint\n";
	cout << "\tadd tcp out block anyip anyip 0 anyip anyip 22 [block outgoing ssh packets]\n";
	cout << "\tdel 2\n";
	cout << endl;
}

/**
 * @name	parse
 * @brief	Parse single command line and execute command
 * @return	True if valid command, False otherwise
 */
bool parse(string line) {
	string cmd = cut_token(line);

	if (cmd == "exit")
		return false;
	else if (cmd ==  "print")
		print_firewall_rules();
	else if (cmd == "add")
		add_firewall_rule(line);
	else if (cmd ==  "del")
		del_firewall_rule(line);
	else
		print_help();

	return true;
}

/**
 * Program entry point
 */
int main(int argc, char *argv[]) {
	string line;

	cout << "Firewall client v0.1" << endl;
	do {
		cout << "> ";
		getline(cin, line);
	} while (parse(line));
}

