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

#ifndef __NAT_STRUCTS_H
#define __NAT_STRUCTS_H


// flow metadata
struct flow_key {
  __be32 src;
  __be32 dst;
  __u16 port16[2];
  __u8 proto;
};

// client's packet metadata
struct packet_description {
  struct flow_key flow;
 __u8 flags;};
  // dscp / ToS value in client's packet
 // __u32 real_index;
  //__u8 tos;
//};


struct binding_definition {
  __be32 addr;
  __u16 port;
};


#endif // of _BALANCER_STRUCTS
