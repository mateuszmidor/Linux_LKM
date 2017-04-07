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

string cut_token(string &src) {
	char head[25] = {'\0'};
	char tail[100] = {'\0'};

	sscanf(src.c_str(), "%s %[^\n]%*c", head, tail);
	src = tail;
	return head;
}

fstream get_module_stream() {
	const string COMMUNICATION_FILEPATH = "/proc/" PROCFS_FILENAME;
	fstream stream(COMMUNICATION_FILEPATH);

	if (!stream)
		cout << "firewall module not running; communication file doesnt exists: " << COMMUNICATION_FILEPATH << endl;

	return stream;
}

void print_firewall_rules() {
	if (fstream stream = get_module_stream())
		cout << stream.rdbuf();
}

void add_firewall_rule(const string &line) {
	firewall_rule tmp;
	if (!deserialize_rule(line.c_str(), &tmp)) {
		cout << "Firewall rule misformatted: " << line << endl;
		return;
	}

	if (fstream stream = get_module_stream())
		stream << "add " << line;
}

void del_firewall_rule(const string &line) {
	unsigned int port;
	if (sscanf(line.c_str(), "%u", &port) != 1) {
		cout << "Port number misformatted: " << line << endl;
		return;
	}

	if (fstream stream = get_module_stream())
		stream << "del " << port;
}

void print_help() {
	cout << "Example commands:\n";
	cout << "\texit\n";
	cout << "\tprint\n";
	cout << "\tadd tcp out block anyip anyip 0 anyip anyip 22\n";
	cout << "\tdel 2\n";
	cout << endl;
}

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

int main(int argc, char *argv[]) {
	string line;

	cout << "Firewall client v0.1" << endl;
	do {
		cout << "> ";
		getline(cin, line);
	} while (parse(line));
}

