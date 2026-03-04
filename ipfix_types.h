//
// Created by andrew on 3/4/26.
//

#ifndef IPFIX_IPFIX_TYPES_H
#define IPFIX_IPFIX_TYPES_H
#include <asm-generic/types.h>
#include <stdbool.h>

typedef struct ipv6_address {
    char bytes[16];
} ipv6_address;

typedef struct mac_address {
    char bytes[12];
} mac_address;


struct ipfix_record {
    __u32 source_ipv4; // 8
    __u32 destination_ipv4; // 12
    __u8 ip_cos; // 5
    __u8 protocol_id; // 4
    __u16 source_port; // 7
    __u16 destination_port; // 11
    __u16 icmp_type_code_ipv4; // 32
    __u32 ingress_interface; // 10
    __u16 vlan_id; // 58
    __u8 source_ipv4_prefix_len; // 9
    __u8 destination_ipv4_prefix_len; // 13
    __u32 bgp_source_asn; // 16
    __u32 bgp_destination_asn; // 17
    __u32 ipv4_next_hop; // 15
    __u64 octet_delta_count; // 1
    __u64 packet_delta_count; // 2
    __u16 tcp_control_bits; // 6
    __u32 egress_interface; // 14
    __u32 bgp_nexthop_ipv4; // 18
    __u8 minimum_ttl; // 52
    __u8 maximum_ttl; // 53
    __u32 fragmentation_id; // 54
    __u8 ip_version; // 60
    __u8 flow_direction; // 61
    __u8 flow_end_reason; // 136
    __u64 flow_start_ms; // 152
    __u64 flow_end_ms; // 153
    __u16 dot1q_vlan_id; // 243
    __u16 dot1q_c_tag; // 245
};
#endif
