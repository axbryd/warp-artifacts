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

#ifndef __NAT_CONSTS_H
#define __NAT_CONSTS_H
/*
 * This file contains definition of all balancer specific constants
 */

// we dont want to do htons for each packet, so this is ETH_P_IPV6 and
// ETH_P_IP in be format
#define BE_ETH_P_IP 8


// 3FFF mask covers more fragments flag and fragment offset field.
// 65343 = 3FFF in BigEndian
#define PCKT_FRAGMENTED 65343

#define F_SYN_SET (1 << 1)
#define NO_FLAGS 0
#define DEFAULT_MAX_ENTRIES_NAT_TABLE 100000
#define MAX_FREE_PORTS_ENTRIES 5000
#define NAT_EXTERNAL_ADDRESS 0xcafebabe
#define FURTHER_PROCESSING -1
#endif // of __BALANCER_CONSTS_H
