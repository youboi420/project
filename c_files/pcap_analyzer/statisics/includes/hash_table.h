#pragma once

#define MAX_HOSTS 100
#define MAX_HOST_LEN 16
#define MAX_PORTS 20
#define MAX_PORT_LEN 6
#define MAX_PROTOCOLS 10

enum type_e {
    TYPE_HOSTS = 101,
    TYPE_PORTS,
};

unsigned int hash(const char *str);
int add_str(char *str, char **table, int type);

int add_port(char *port, char portss[MAX_PORTS][MAX_PORT_LEN]);
void init_ports_table(char table[MAX_PORTS][MAX_PORT_LEN]);
void print_ports_table(char ports[MAX_PORTS][MAX_PORT_LEN], int num_ports);
void init_table(char **table, int size, int limit);

int add_host(char *host, char hosts[MAX_PORT_LEN][MAX_HOST_LEN]);
void init_hosts_table(char hosts[MAX_HOSTS][MAX_HOST_LEN]);
void print_hosts_table(char hosts[MAX_HOSTS][MAX_HOST_LEN], int num_hosts);