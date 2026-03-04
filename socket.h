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

#define OCTET_DELTA_COUNT 1
#define PACKET_DELTA_COUNT 2
#define PROTOCOL 4
#define COS 5
#define TCP_CONTROL_BITS 6
#define SRC_PORT 7
#define SRC_ADDR 8
#define SOURCE_PREFIX_LEN 9
#define INGRESS_INTERFACE 10
#define DST_PORT 11
#define DST_ADDR 12
#define DST_PREFIX_LEN 13
#define EGRESS_INTERFACE 14
#define IPV4_NH_ADDR 15
#define BGP_SOURCE_ASN 16
#define BGP_DEST_ASN 17
#define BGP_NEXTHOP_IPV4 18
#define ICMP_TYPE_CODE 32
#define MINIMUM_TTL 52
#define MAXIMUM_TTL 53
#define FRAGMENT_ID 54
#define VLAN_ID 58
#define IP_VERSION 60
#define FLOW_DIRECTION 61
#define FLOW_END_REASON 136
#define FLOW_START_MS 152
#define FLOW_END_MS 153
#define DOT1Q_VLAN_ID 243
#define DOT1Q_CVLAN_ID 245

void *read_socket(void *data);

#endif 

