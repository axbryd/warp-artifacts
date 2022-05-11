/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __NAT_PCKT_PARSING_H
#define __NAT_PCKT_PARSING_H

/*
 * This file contains generic packet parsing routines (e.g. tcp/udp headers
 * parsing etc)
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ptrace.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "nat_consts.h"

struct eth_hdr {
  unsigned char eth_dest[ETH_ALEN];
  unsigned char eth_source[ETH_ALEN];
  unsigned short  eth_proto;
};


__attribute__((__always_inline__))
static inline __u64 calc_offset(bool is_ipv6, bool is_icmp) {
  __u64 off = sizeof(struct eth_hdr);
  if (is_ipv6) {
    off += sizeof(struct ipv6hdr);
    if (is_icmp) {
      off += (sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
    }
  } else {
    off += sizeof(struct iphdr);
    if (is_icmp) {
      off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
    }
  }
  return off;
}



#endif // of  __PCKT_PARSING_H
