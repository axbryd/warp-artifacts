/*
 * Copyright 2022 Axbryd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <time.h>
#include "helper_functions.h"
#include "ubpf_hashmap.h"

struct ubpf_func_proto ubpf_map_lookup_proto = {
        .func = (ext_func)ubpf_map_lookup,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR | UNKNOWN,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                0xff,
                0xff,
                0xff,
        },
        .ret = MAP_VALUE_PTR | NULL_VALUE,
};

void *
ubpf_map_lookup(const struct ubpf_map *map, void *key)
{
    if (!map) {
        return NULL;
    }
    if (!map->ops.map_lookup) {
        return NULL;
    }
    if (!key) {
        return NULL;
    }
    return map->ops.map_lookup(map, key);
}

struct ubpf_func_proto ubpf_map_update_proto = {
        .func = (ext_func)ubpf_map_update,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                SIZE_MAP_VALUE,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

int
ubpf_map_update(struct ubpf_map *map, const void *key, void *item)
{
    if (!map) {
        return -1;
    }
    if (!map->ops.map_update) {
        return -2;
    }
    if (!key) {
        return -3;
    }
    if (!item) {
        return -4;
    }
    return map->ops.map_update(map, key, item);
}

struct ubpf_func_proto ubpf_map_add_proto = {
        .func = (ext_func)ubpf_map_add,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_VALUE,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

int
ubpf_map_add(struct ubpf_map *map, void *item)
{
    if (!map) {
        return -1;
    }
    if (!map->ops.map_add) {
        return -2;
    }
    if (!item) {
        return -3;
    }
    return map->ops.map_add(map, item);
}

struct ubpf_func_proto ubpf_map_delete_proto = {
        .func = (ext_func)ubpf_map_delete,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

int
ubpf_map_delete(struct ubpf_map *map, const void *key)
{
    if (!map) {
        return -1;
    }
    if (!map->ops.map_delete) {
        return -2;
    }
    if (!key) {
        return -3;
    }
    return map->ops.map_delete(map, key);
}

struct ubpf_func_proto ubpf_time_get_ns_proto = {
        .func = (ext_func)ubpf_time_get_ns,
        .arg_types = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

uint64_t
ubpf_time_get_ns(void)
{
    struct timespec curr_time = {0, 0};
    uint64_t curr_time_ns = 0;
    clock_gettime(CLOCK_REALTIME, &curr_time);
    curr_time_ns = curr_time.tv_nsec + curr_time.tv_sec * 1.0e9;
    return curr_time_ns;
}

struct ubpf_func_proto ubpf_hash_proto = {
        .func = (ext_func)ubpf_hash,
        .arg_types = {
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                IMM,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                SIZE_PTR_MAX,
                SIZE_64,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

uint32_t
ubpf_hash(void *item, uint64_t size)
{
    return hashlittle(item, (uint32_t)size, 0);
}

struct ubpf_func_proto ubpf_get_smp_processor_id_proto = {
        .func = (ext_func)ubpf_get_smp_processor_id,
        .arg_types = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

uint64_t
ubpf_get_smp_processor_id() {
    return 0;
}

struct ubpf_func_proto ubpf_csum_diff_proto = {
        .func = (ext_func)ubpf_csum_diff,
        .arg_types = {
                PKT_PTR,
                IMM,
                PKT_PTR,
                IMM,
                IMM,
        },
        .arg_sizes = {
                SIZE_PTR_MAX,
                SIZE_64,
                SIZE_PTR_MAX,
                SIZE_64,
                SIZE_64,
        },
        .ret = UNKNOWN,
};

static inline unsigned short from64to16(unsigned long x)
{
    /* Using extract instructions is a bit more efficient
       than the original shift/bitmask version.  */

    union {
      unsigned long	ul;
      unsigned int	ui[2];
      unsigned short	us[4];
    } in_v, tmp_v, out_v;

    in_v.ul = x;
    tmp_v.ul = (unsigned long) in_v.ui[0] + (unsigned long) in_v.ui[1];

    /* Since the bits of tmp_v.sh[3] are going to always be zero,
       we don't have to bother to add that in.  */
    out_v.ul = (unsigned long) tmp_v.us[0] + (unsigned long) tmp_v.us[1]
               + (unsigned long) tmp_v.us[2];

    /* Similarly, out_v.us[2] is always zero for the final add.  */
    return out_v.us[0] + out_v.us[1];
}


static inline unsigned long do_csum(const unsigned char * buff, int len)
{
    int odd, count;
    unsigned long result = 0;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long) buff;
    if (odd) {
        result = *buff << 8;
        len--;
        buff++;
    }
    count = len >> 1;		/* nr of 16-bit words.. */
    if (count) {
        if (2 & (unsigned long) buff) {
            result += *(unsigned short *) buff;
            count--;
            len -= 2;
            buff += 2;
        }
        count >>= 1;		/* nr of 32-bit words.. */
        if (count) {
            if (4 & (unsigned long) buff) {
                result += *(unsigned int *) buff;
                count--;
                len -= 4;
                buff += 4;
            }
            count >>= 1;	/* nr of 64-bit words.. */
            if (count) {
                unsigned long carry = 0;
                do {
                    unsigned long w = *(unsigned long *) buff;
                    count--;
                    buff += 8;
                    result += carry;
                    result += w;
                    carry = (w > result);
                } while (count);
                result += carry;
                result = (result & 0xffffffff) + (result >> 32);
            }
            if (len & 4) {
                result += *(unsigned int *) buff;
                buff += 4;
            }
        }
        if (len & 2) {
            result += *(unsigned short *) buff;
            buff += 2;
        }
    }
    if (len & 1)
        result += *buff;
    result = from64to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
    out:
    return result;
}

uint64_t
csum_partial(const void *buff, int len, uint64_t seed)
{
    unsigned int sum = (unsigned int) seed;
    unsigned int result = do_csum(buff, len);

    /* add in old sum, and carry.. */
    result += sum;
    if (sum > result)
        result += 1;
    return (uint64_t)result;
}

uint64_t
ubpf_csum_diff(uint64_t r1, uint64_t from_size,
               uint64_t r3, uint64_t to_size, uint64_t seed) {
    uint32_t *from = (uint32_t *) (long) r1;
    uint32_t *to = (uint32_t *) (long) r3;
    uint64_t diff_size = from_size + to_size;
    uint32_t diff[diff_size/ sizeof(uint32_t)];

    int i, j = 0;

    for (i = 0; i < from_size / sizeof(uint32_t); i++, j++)
        diff[j] = ~from[i];
    for (i = 0; i <   to_size / sizeof(uint32_t); i++, j++)
        diff[j] = to[i];

    return csum_partial(diff, diff_size, seed);
}

struct ubpf_func_proto ubpf_xdp_adjust_head_proto = {
        .func = (ext_func)ubpf_xdp_adjust_head,
        .arg_types = {
                XDP_MD_PTR,
                IMM,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                SIZE_PTR_MAX,
                SIZE_64,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

uint64_t
ubpf_xdp_adjust_head(void *xdp, uint64_t size) {
    int _size = (int) (size);
    struct xdp_md *_xdp = (struct xdp_md *)xdp;

    if (_size < -PKT_HEADROOM || _size > PKT_HEADROOM) {
        return -1;
    } else {
        _xdp->data += _size;
        return 0;
    }
}

struct ubpf_func_proto ubpf_xdp_adjust_tail_proto = {
        .func = (ext_func)ubpf_xdp_adjust_tail,
        .arg_types = {
                XDP_MD_PTR,
                IMM,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                SIZE_PTR_MAX,
                SIZE_64,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

uint64_t
ubpf_xdp_adjust_tail(void *xdp, uint64_t size) {
    int _size = (int) (size);
    struct xdp_md *_xdp = (struct xdp_md *)xdp;

    if (_size < -PKT_TAILROOM || _size > PKT_TAILROOM) {
        return -1;
    } else {
        _xdp->data_end += _size;
        return 0;
    }
}

struct ubpf_func_proto ubpf_redirect_map_proto = {
        .func = (ext_func)ubpf_redirect_map,
        .arg_types = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

uint64_t
ubpf_redirect_map() {
    return 3;
}

void
register_functions(struct ubpf_vm *vm)
{
    ubpf_register_function(vm, MAP_LOOKUP, "ubpf_map_lookup", ubpf_map_lookup_proto);
    ubpf_register_function(vm, MAP_UPDATE, "ubpf_map_update", ubpf_map_update_proto);
    ubpf_register_function(vm, MAP_DELETE, "ubpf_map_delete", ubpf_map_delete_proto);
    ubpf_register_function(vm, MAP_ADD, "ubpf_map_add", ubpf_map_add_proto);
    ubpf_register_function(vm, TIME_GET_NS, "ubpf_time_get_ns", ubpf_time_get_ns_proto);
    ubpf_register_function(vm, HASH, "ubpf_hash", ubpf_hash_proto);
    ubpf_register_function(vm, GET_SMP_PROCESSOR_ID, "ubpf_get_smp_processor_id", ubpf_get_smp_processor_id_proto);
    ubpf_register_function(vm, CSUM_DIFF, "ubpf_csum_diff", ubpf_csum_diff_proto);
    ubpf_register_function(vm, XDP_ADJUST_HEAD, "ubpf_adjust_head", ubpf_xdp_adjust_head_proto);
    ubpf_register_function(vm, XDP_ADJUST_TAIL, "ubpf_adjust_tail", ubpf_xdp_adjust_tail_proto);
    ubpf_register_function(vm, REDIRECT_MAP, "ubpf_redirect_map", ubpf_redirect_map_proto);

}
