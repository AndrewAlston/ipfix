//
// Created by andrew on 3/4/26.
//

#ifndef IPFIX_IPFIX_TYPES_H
#define IPFIX_IPFIX_TYPES_H
#include <asm-generic/types.h>
#include <stdbool.h>

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
#define SRC_ADDR_V6 27
#define DST_ADDR_V6 28
#define SRC_ADDR_V6_PREFIX_LEN 29
#define DST_ADDR_V6_PREFIX_LEN 30
#define ICMP_TYPE_CODE 32
#define MINIMUM_TTL 52
#define MAXIMUM_TTL 53
#define FRAGMENT_ID 54
#define VLAN_ID 58
#define IP_VERSION 60
#define FLOW_DIRECTION 61
#define NEXTHOP_IPV6 62
#define NEXTHOP_BGP_IPV6 63
#define EXTENSION_HEADERS_IPV6 64
#define FLOW_END_REASON 136
#define ICMP_TYPE_CODE_IPV6 139
#define FLOW_START_MS 152
#define FLOW_END_MS 153
#define DOT1Q_VLAN_ID 243
#define DOT1Q_CVLAN_ID 245

typedef struct ipv6_address {
    char bytes[16];
} ipv6_address;

typedef struct mac_address {
    char bytes[12];
} mac_address;


struct ipfix_record_v6 {
    __u64 octet_delta_count; // 1
    __u64 packet_delta_count; // 2
    __u8 protocol_id; // 4
    __u8 ip_cos; // 5
    __u16 tcp_control_bits; // 6
    __u16 source_port; // 7
    __u32 ingress_interface; // 10
    __u16 destination_port; // 11
    __u32 egress_interface; // 14
    __u32 bgp_source_asn; // 16
    __u32 bgp_destination_asn; // 17
    __u8 source_ipv6[16]; // 27
    __u8 destination_ipv6[16]; // 28
    __u8 ipv6_source_prefix_len; // 29
    __u8 ipv6_destination_prefix_len; // 30
    __u8 minimum_ttl; // 52
    __u8 maximum_ttl; // 53
    __u32 fragmentation_id; // 54
    __u16 vlan_id; // 58
    __u8 flow_direction; // 61
    __u8 ipv6_nexthop[16]; // 62
    __u8 ipv6_bgp_nexthop[16]; // 63
    __u32 ipv6_extension_headers; // 64
    __u8 flow_end_reason; // 136
    __u16 ipv6_icmp_type_code; // 139
    __u64 flow_start_ms; // 152
    __u64 flow_end_ms; // 153
    __u16 dot1q_vlan_id; // 243
    __u16 dot1q_c_tag; // 245
};

struct ipfix_record_v4 {
    __u64 octet_delta_count; // 1
    __u64 packet_delta_count; // 2
    __u8 protocol_id; // 4
    __u8 ip_cos; // 5
    __u16 tcp_control_bits; // 6
    __u16 source_port; // 7
    __u32 source_ipv4; // 8
    __u8 source_ipv4_prefix_len; // 9
    __u32 ingress_interface; // 10
    __u16 destination_port; // 11
    __u32 destination_ipv4; // 12
    __u8 destination_ipv4_prefix_len; // 13
    __u32 egress_interface; // 14
    __u32 ipv4_next_hop; // 15
    __u32 bgp_source_asn; // 16
    __u32 bgp_destination_asn; // 17
    __u32 bgp_nexthop_ipv4; // 18
    __u16 icmp_type_code_ipv4; // 32
    __u8 minimum_ttl; // 52
    __u8 maximum_ttl; // 53
    __u32 fragmentation_id; // 54
    __u16 vlan_id; // 58
    __u8 ip_version; // 60
    __u8 flow_direction; // 61
    __u8 flow_end_reason; // 136
    __u64 flow_start_ms; // 152
    __u64 flow_end_ms; // 153
    __u16 dot1q_vlan_id; // 243
    __u16 dot1q_c_tag; // 245
};
#endif
