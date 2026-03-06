//
// Created by andrew on 3/4/26.
//

#include "socket.h"
#include "ipfix_types.h"

void dump_buffer(void *buffer, __u16 size) {
    char ret_print[18];
    void *cur_pkt = buffer;
    printf("%06x\t", 0);
    fflush(stdout);
    for (int p = 0; p < size; p++) {
        if ((p + 1) % 16 == 0)
            snprintf(ret_print, 10, "\n%06x\t", p + 1);
        printf("%02x%s", *(uint8_t *) (cur_pkt + p),
               ((p + 1) % 16 == 0) ? ret_print : " ");
        fflush(stdout);
    }
    printf("\n\n");
    fflush(stdout);
}

#define SET_PTR(offset, element) ({ ptrs[(offset)] = &(element); \
    lengths[(offset)] = length; \
    types[(offset)] = type; break; })

void set_template_ptrs_v4(const struct ipfix_header *hdr, const char *buffer, struct ipfix_record_v4 *r, void **ptrs,
                       u_char *lengths, u_char *types) {
    for (int i = 0; i < htons(hdr->field_count); i++) {
        __u16 type = htons(*(__u16*)buffer);
       const  __u16 length = htons(*(__u16*)(buffer+2));
        switch (type) {
            case OCTET_DELTA_COUNT:
                SET_PTR(i, r->octet_delta_count);
            case PACKET_DELTA_COUNT:
                SET_PTR(i, r->packet_delta_count);
            case PROTOCOL:
                SET_PTR(i, r->protocol_id);
            case COS:
                SET_PTR(i, r->ip_cos);
            case TCP_CONTROL_BITS:
                SET_PTR(i, r->tcp_control_bits);
            case SRC_PORT:
                SET_PTR(i, r->source_port);
            case SRC_ADDR:
                SET_PTR(i, r->source_ipv4);
            case SOURCE_PREFIX_LEN:
                SET_PTR(i, r->source_ipv4_prefix_len);
            case INGRESS_INTERFACE:
                SET_PTR(i, r->ingress_interface);
            case DST_PORT:
                SET_PTR(i, r->destination_port);
            case DST_ADDR:
                SET_PTR(i, r->destination_ipv4);
            case DST_PREFIX_LEN:
                SET_PTR(i, r->destination_ipv4_prefix_len);
            case EGRESS_INTERFACE:
                SET_PTR(i, r->egress_interface);
            case IPV4_NH_ADDR:
                SET_PTR(i, r->ipv4_next_hop);
            case BGP_SOURCE_ASN:
                SET_PTR(i, r->bgp_source_asn);
            case BGP_DEST_ASN:
                SET_PTR(i, r->bgp_destination_asn);
            case BGP_NEXTHOP_IPV4:
                SET_PTR(i, r->bgp_nexthop_ipv4);
            case ICMP_TYPE_CODE:
                SET_PTR(i, r->icmp_type_code_ipv4);
            case MINIMUM_TTL:
                SET_PTR(i, r->minimum_ttl);
            case MAXIMUM_TTL:
                SET_PTR(i, r->maximum_ttl);
            case FRAGMENT_ID:
                SET_PTR(i, r->fragmentation_id);
            case VLAN_ID:
                SET_PTR(i, r->vlan_id);
            case IP_VERSION:
                SET_PTR(i, r->ip_version);
            case FLOW_DIRECTION:
                SET_PTR(i, r->flow_direction);
            case FLOW_END_REASON:
                SET_PTR(i, r->flow_end_reason);
            case FLOW_START_MS:
                SET_PTR(i, r->flow_start_ms);
            case FLOW_END_MS:
                SET_PTR(i, r->flow_end_ms);
            case DOT1Q_VLAN_ID:
                SET_PTR(i, r->dot1q_vlan_id);
            case DOT1Q_CVLAN_ID:
                SET_PTR(i, r->dot1q_c_tag);
            default:
                printf("Received unknown ipfix element %d\n", type);
        }
        buffer += 4;
    }
}

void set_template_ptrs_v6(const struct ipfix_header *hdr, const char *buffer, struct ipfix_record_v6 *r, void **ptrs,
                       u_char *lengths, u_char *types) {
    for (int i = 0; i < htons(hdr->field_count); i++) {
        __u16 type = htons(*(__u16*)buffer);
       const  __u16 length = htons(*(__u16*)(buffer+2));
        switch (type) {
            case OCTET_DELTA_COUNT:
                SET_PTR(i, r->octet_delta_count);
            case PACKET_DELTA_COUNT:
                SET_PTR(i, r->packet_delta_count);
            case PROTOCOL:
                SET_PTR(i, r->protocol_id);
            case COS:
                SET_PTR(i, r->ip_cos);
            case TCP_CONTROL_BITS:
                SET_PTR(i, r->tcp_control_bits);
            case SRC_PORT:
                SET_PTR(i, r->source_port);
            case SRC_ADDR_V6:
                SET_PTR(i, r->source_ipv6);
            case SRC_ADDR_V6_PREFIX_LEN:
                SET_PTR(i, r->ipv6_source_prefix_len);
            case INGRESS_INTERFACE:
                SET_PTR(i, r->ingress_interface);
            case DST_PORT:
                SET_PTR(i, r->destination_port);
            case DST_ADDR_V6:
                SET_PTR(i, r->destination_ipv6);
            case DST_ADDR_V6_PREFIX_LEN:
                SET_PTR(i, r->ipv6_destination_prefix_len);
            case EGRESS_INTERFACE:
                SET_PTR(i, r->egress_interface);
            case NEXTHOP_IPV6:
                SET_PTR(i, r->ipv6_nexthop);
            case BGP_SOURCE_ASN:
                SET_PTR(i, r->bgp_source_asn);
            case BGP_DEST_ASN:
                SET_PTR(i, r->bgp_destination_asn);
            case NEXTHOP_BGP_IPV6:
                SET_PTR(i, r->ipv6_bgp_nexthop);
            case ICMP_TYPE_CODE:
                SET_PTR(i, r->ipv6_icmp_type_code);
            case MINIMUM_TTL:
                SET_PTR(i, r->minimum_ttl);
            case MAXIMUM_TTL:
                SET_PTR(i, r->maximum_ttl);
            case FRAGMENT_ID:
                SET_PTR(i, r->fragmentation_id);
            case VLAN_ID:
                SET_PTR(i, r->vlan_id);
            case FLOW_DIRECTION:
                SET_PTR(i, r->flow_direction);
            case FLOW_END_REASON:
                SET_PTR(i, r->flow_end_reason);
            case FLOW_START_MS:
                SET_PTR(i, r->flow_start_ms);
            case FLOW_END_MS:
                SET_PTR(i, r->flow_end_ms);
            case DOT1Q_VLAN_ID:
                SET_PTR(i, r->dot1q_vlan_id);
            case DOT1Q_CVLAN_ID:
                SET_PTR(i, r->dot1q_c_tag);
            case EXTENSION_HEADERS_IPV6:
                SET_PTR(i, r->ipv6_extension_headers);
            case ICMP_TYPE_CODE_IPV6:
                SET_PTR(i, r->ipv6_icmp_type_code);
            default:
                printf("Received unknown ipfix element %d\n", type);
        }
        buffer += 4;
    }
}

void *read_socket_v6(void *data) {
    struct sock_set *s = data;
    struct ipfix_record_v6 tmp_record;
    struct ipfix_record_v6 records[512];
    u_char lengths[29];
    s->slen = sizeof(s->si_other);
    if ((s->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        s->error = true;
        snprintf(s->errstr, 2048, "Failed creating socket");
        return s;
    }
    char read_buf[s->buf_size];
    memset(read_buf, 0, s->buf_size);
    char buf_copy[65535];
    u_char types[529];
    if ((s->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        s->error = true;
        snprintf(s->errstr, 2048, "Failed creating socket");
        return s;
    }
    memset((char *)&s->si_me, 0, sizeof(s->si_me));
    s->si_me.sin_family = AF_INET;
    s->si_me.sin_port = htons(s->port);
    s->si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s->socket, (struct sockaddr *)&s->si_me, sizeof(s->si_me)) == -1) {
        s->error = true;
        snprintf(s->errstr, 2048, "[IPv6] Failed binding socket");
        return s;
    }
    ssize_t total_read = 0;
    void *element_ptrs[29] = {0};
    __u16 field_count = 0;
    bool have_template = false;
    while (!s->shutdown) {
        memset(read_buf, 0, s->buf_size);
        ssize_t nread = recvfrom(s->socket, read_buf, s->buf_size, 0,
            (struct sockaddr *)&s->si_other, &s->slen);
        if (nread == -1)
            return s;
        struct ipfix_header *hdr = (void *)read_buf;
        if (htons(hdr->version) == 10) {
            if (htons(hdr->flowset_id) == 2) {
                printf("[IPv6] Got IP-FIX Version 10 template [%d length]\n", htons(hdr->flowset_length));
                printf("[IPv6] Flow sequence %d, observation id %d, flowset id %d, template id %d, field count %d\n",
                       htonl(hdr->flow_sequence), htonl(hdr->domain_id), htons(hdr->flowset_id),
                       htons(hdr->template_id),
                       htons(hdr->field_count));
                char *template_start = &read_buf[sizeof(struct ipfix_header)];
                set_template_ptrs_v6(hdr, template_start, &tmp_record, element_ptrs, lengths, types);
                field_count = htons(hdr->field_count);
                have_template = true;
                continue;
            }
            if (have_template) {
                char *data_start = &read_buf[sizeof(struct ipfix_data_header)];
                char *data_end = &read_buf[htons(hdr->length)];
                int flow_count = 0;
                while (data_start < data_end) {
                    for (int i = 0; i < field_count; i++) {
                        memcpy(element_ptrs[i], data_start, lengths[i]);
                        data_start += lengths[i];
                    }
                    memset(&records[flow_count], 0, sizeof(struct ipfix_record_v6));
                    memcpy(&records[flow_count++], &tmp_record, sizeof(struct ipfix_record_v6));
                }
                for (int i = 0; i < flow_count; i++) {
                    char ip6_src[INET6_ADDRSTRLEN];
                    char ip6_dst[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &records[i].source_ipv6, ip6_src, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &records[i].destination_ipv6, ip6_dst, INET6_ADDRSTRLEN);
                    printf("[Protocol %d] %s:%u -> %s:%u [SRC ASN: %d -> DST ASN: %d]\n",
                           records[i].protocol_id, ip6_src, htons(records[i].source_port),
                           ip6_dst, htons(records[i].destination_port),
                           htonl(records[i].bgp_source_asn), htonl(records[i].bgp_destination_asn));
                }
            }
        }
    }
    return s;
}

void *read_socket_v4(void *data) {
    struct sock_set *s = data;
    char *template_start = NULL;
    struct ipfix_record_v4 tmp_record;
    struct ipfix_record_v4 records[512];
    u_char lengths[29];
    s->slen = sizeof(s->si_other);
    char read_buf[s->buf_size];
    memset(read_buf, 0, s->buf_size);
    bool have_template = false;
    char buf_copy[65535];
    u_char types[529];
    if ((s->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        s->error = true;
        snprintf(s->errstr, 2048, "Failed creating socket");
        return s;
    }
    memset((char *) &s->si_me, 0, sizeof(s->si_me));
    s->si_me.sin_family = AF_INET;
    s->si_me.sin_port = htons(s->port);
    s->si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s->socket, (struct sockaddr *) &s->si_me, sizeof(s->si_me)) == -1) {
        s->error = true;
        snprintf(s->errstr, 2048, "[IPv4] Failed binding socket");
        return s;
    }
    ssize_t total_read = 0;
    void *element_ptrs[29] = {0};
    __u16 field_count = 0;
    while (!s->shutdown) {
        int record_num = 0;
        if (total_read + s->buf_size > s->buf_len) {
            memset(buf_copy, 0, sizeof(buf_copy));
            memcpy(buf_copy, s->buf, total_read);
            dump_buffer(s->buf, total_read);
            memset(s->buf, 0, s->buf_size);
            total_read = 0;
        }
        ssize_t nread = recvfrom(s->socket, read_buf, s->buf_size, 0,
                                 (struct sockaddr *) &s->si_other, &s->slen);
        if (nread == -1)
            return s;
        struct ipfix_header *hdr = (void *) read_buf;
        if (htons(hdr->version) == 10) {
            if (htons(hdr->flowset_id) == 2) {
                printf("[IPv4] Got IP-FIX Version 10 template [%d length]\n", htons(hdr->flowset_length));
                printf("[IPv4] Flow sequence %d, observation id %d, flowset id %d, template id %d, field count %d\n",
                       htonl(hdr->flow_sequence), htonl(hdr->domain_id), htons(hdr->flowset_id),
                       htons(hdr->template_id),
                       htons(hdr->field_count));
                template_start = &read_buf[sizeof(struct ipfix_header)];
                set_template_ptrs_v4(hdr, template_start, &tmp_record, element_ptrs, lengths, types);
                field_count = htons(hdr->field_count);
                have_template = true;
                continue;
            }
            if (have_template) {
                struct ipfix_data_header d_hdr;
                char *data_start = &read_buf[sizeof(d_hdr)];
                char *data_end = &read_buf[htons(hdr->length)];
                int flow_count = 0;
                while (data_start < data_end) {
                    for (int i = 0; i < field_count; i++) {
                        memcpy(element_ptrs[i], data_start, lengths[i]);
                        data_start += lengths[i];
                    }
                    memcpy(&records[flow_count++], &tmp_record, sizeof(tmp_record));
                }
                bool have_interface = false;
                char unknown_interface[256] = "Unknown";
                char router[256] = {0};
                __u8 *did = (void *)&hdr->domain_id;
                if (did[0] == 10) {
                    snprintf(router, 256, "ICOLO-MX204");
                } else if (did[0] == 15) {
                    snprintf(router, 256, "ICOLO-ACX7100");
                } else {
                    snprintf(router, 256, "UNKNOWN");
                }
                for (int i = 0; i < flow_count; i++) {
                    __u32 dip = ntohl(records[i].destination_ipv4);
                    __u32 source_asn = htonl(records[i].bgp_source_asn);
                    // if (source_asn == 30844 || source_asn == 36937 || source_asn == 37006) {
                    if (source_asn == 15169) {
                        char ip_src[INET_ADDRSTRLEN] = {0};
                        char ip_dst[INET_ADDRSTRLEN] = {0};
                        __u32 mask = htonl((~(__u32)0) << (32-records[i].source_ipv4_prefix_len));
                        records[i].source_ipv4 = records[i].source_ipv4&mask;
                        mask = htonl((~(__u32)0) << (32-records[i].destination_ipv4_prefix_len));
                        records[i].destination_ipv4 = records[i].destination_ipv4&mask;
                        inet_ntop(AF_INET, &records[i].source_ipv4, ip_src, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &records[i].destination_ipv4, ip_dst, INET_ADDRSTRLEN);
                        __u32 ingress = htonl(records[i].ingress_interface);
                        char *iface = NULL;
                        if (did[0] == 10) {
                            for (int inif = 0; inif < 11; inif++) {
                                if (ifaces[inif].ifindex == ingress) {
                                    iface = ifaces[inif].if_name;
                                    have_interface = true;
                                    break;
                                }
                            }
                        } else if (did[0] == 15) {
                            for (int inif = 0; inif < 52; inif++) {
                                if (ifaces_acx7100[inif].ifindex == ingress) {
                                    iface = ifaces_acx7100[inif].if_name;
                                    have_interface = true;
                                    break;
                                }
                            }
                        }
                        if (!have_interface) {
                            iface = unknown_interface;
                        }
                        printf("[%s] [Protocol %d] [Interface %s] %s/%d -> %s/%d [SRC ASN: %d -> DST ASN: %d]\n",
                               router, records[i].protocol_id, iface,  ip_src, records[i].source_ipv4_prefix_len,
                               ip_dst, records[i].destination_ipv4_prefix_len,
                               htonl(records[i].bgp_source_asn), htonl(records[i].bgp_destination_asn));
                    }
                }
            }
        }
    }
    return s;
}

