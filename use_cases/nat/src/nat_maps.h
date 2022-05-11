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

#ifndef __NAT_MAPS_H
#define __NAT_MAPS_H

/*
 * This file contains definition of all maps which has been used by balancer
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "nat_consts.h"
#include "nat_structs.h"

// nat binding tables
struct bpf_map_def SEC("maps") nat_binding_table = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct flow_key),
  .value_size = sizeof(struct binding_definition),
  .max_entries = DEFAULT_MAX_ENTRIES_NAT_TABLE,
  .map_flags = NO_FLAGS,
};
//BPF_ANNOTATE_KV_PAIR(nat_binding_table, struct flow_key, struct binding_definition);

// map which contains 1 elemnent with the last idx for the free_port array
struct bpf_map_def SEC("maps") last_free_port_idx = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = 1,
  .map_flags = NO_FLAGS,
};
//BPF_ANNOTATE_KV_PAIR(last_free_port_idx, __u32, __u32);

// map which contains the free_port list
struct bpf_map_def SEC("maps") free_ports = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u16),
  .max_entries = MAX_FREE_PORTS_ENTRIES,
  .map_flags = NO_FLAGS,
};
//BPF_ANNOTATE_KV_PAIR(free_ports, __u32, __u16);

#endif // of _NAT_MAPS
