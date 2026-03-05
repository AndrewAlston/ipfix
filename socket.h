// Created by andrew on 3/4/26.
//

#ifndef IPFIX_SOCKET_H
#define IPFIX_SOCKET_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm-generic/types.h>
#include <stdbool.h>

struct sock_set {
    __u16 port;
    __u16 buf_size;
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    socklen_t slen;
    char buf[65535];
    int buf_len;
    int socket;
    char errstr[2048];
    bool error;
    bool shutdown;
};

struct sock_set6 {
    __u16 port;
    __u16 buf_size;
    struct sockaddr_in6 si_me;
    struct sockaddr_in6 si_other;
    socklen_t slen;
    char buf[65535];
    int buf_len;
    int socket;
    char errstr[2048];
    bool error;
    bool shutdown;
};

struct ipfix_header {
    __u16 version;
    __u16 length;
    __u32 timestamp;
    __u32 flow_sequence;
    __u32 domain_id;
    __u16 flowset_id;
    __u16 flowset_length;
    __u16 template_id;
    __u16 field_count;
} __attribute__((__packed__));

struct ipfix_data_header {
    __u16 version;
    __u16 length;
    __u32 timestamp;
    __u32 flow_Sequence;
    __u32 domain_id;
    __u16 flowset_id;
    __u16 flowset_length;
} __attribute__((__packed__));

struct template_data {
    __u16 type[529];
    __u16 length[529];
};



void *read_socket_v4(void *data);
void *read_socket_v6(void *data);

#endif 

