#include "../includes/hash_table.h"
#include <stdio.h>
#include <string.h>

unsigned int hash(const char *str)
{
    unsigned int hash = 5381; int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % MAX_HOSTS;
}

int add_host(char *host, char hosts[MAX_HOSTS][MAX_HOST_LEN])
{
    unsigned int index = hash(host); int probe_index, i;

    for (i = 0; i < MAX_HOSTS; i++) {
        probe_index = (index + i) % MAX_HOSTS;
        if (strcmp(hosts[probe_index], "") == 0) {
            strncpy(hosts[probe_index], host, MAX_HOST_LEN);
            return 1;  /* added */
        } else if (strcmp(hosts[probe_index], host) == 0) {
            return 0; /* dup */
        }
    }
    return -1; /* hosts is NULL? */
}

int add_port(char *port, char ports[MAX_PORTS][MAX_PORT_LEN])
{
    unsigned int index = hash(port) % MAX_PORTS; int probe_index, i;

    for (i = 0; i < MAX_PORTS; i++) {
        probe_index = (index + i) % MAX_PORTS;
        if (strcmp(ports[probe_index], "") == 0) {
            strncpy(ports[probe_index], port, MAX_PORT_LEN);
            return 1;  /* added */
        } else if (strcmp(ports[probe_index], port) == 0) {
            return 0; /* dup */
        }
    }
    return -1; /* ports is NULL? */
}

void init_hosts_table(char hosts[MAX_HOSTS][MAX_HOST_LEN])
{
    int i;
    for (i = 0; i < MAX_HOSTS; i++)
    {
        hosts[i][0] = '\0';
    }
}

void init_ports_table(char ports[MAX_PORTS][MAX_PORT_LEN])
{
    int i;
    for (i = 0; i < MAX_HOSTS; i++)
    {
        ports[i][0] = '\0';
    }
}

void print_hosts_table(char hosts[MAX_HOSTS][MAX_HOST_LEN], int num_hosts)
{
    int i, count = 0;
    printf("\n------------TABLE START--------------\n");
    for (i = 0; i < MAX_HOSTS; i++)
    {
        if (count >= num_hosts)
            break;
        else if (strncmp(hosts[i], "", MAX_HOST_LEN) != 0)
        {
            printf("[+] HOST IP: %s\n", hosts[i]);
            count++;
        }
    }
    printf("[+] there are [%i/%i] hosts\n", num_hosts, MAX_HOSTS);
    printf("-------------TABLE END---------------\n");
}

void print_ports_table(char ports[MAX_PORTS][MAX_PORT_LEN], int num_ports)
{
    int i, count = 0;
    printf("\n------------TABLE START--------------\n");
    for (i = 0; i < MAX_PORTS; i++)
    {
        if (count >= num_ports)
            break;
        else if (strncmp(ports[i], "", MAX_PORT_LEN) != 0)
        {
            printf("[+] PORT: %s\n", ports[i]);
            count++;
        }
    }
    printf("[+] there are [%i/%i] ports\n", num_ports, MAX_PORTS);
    printf("-------------TABLE END---------------\n");
}