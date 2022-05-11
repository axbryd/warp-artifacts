/*
 * Copyright 2018 Orange
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sclog4c.h>
#include "inttypes.h"

//#include <config.h>
//#include "util.h"

#include "ubpf_int.h"

void *ubpf_array_create(const struct ubpf_map *map);
static void *ubpf_array_lookup(const struct ubpf_map *map, const void *key);
static int ubpf_array_update(struct ubpf_map *map, const void *key,
                             void *value);

static inline uint64_t
log2u(uint64_t x) {
    uint64_t res = 0;

    while(x >>= 1) res++;

    return res;
}

const struct ubpf_map_ops ubpf_array_ops = {
    .map_lookup = ubpf_array_lookup,
    .map_update = ubpf_array_update,
    .map_delete = NULL,
    .map_add = NULL,
};

void *
ubpf_array_create(const struct ubpf_map *map)
{
    return calloc(map->max_entries, map->value_size);
}

static void *
ubpf_array_lookup(const struct ubpf_map *map, const void *key)
{
    uint64_t mask = (1lu << (log2u(map->max_entries))) - 1lu;
    uintptr_t ret;

    uint64_t idx = *((const uint64_t *)key) & mask;
    if (idx >= map->max_entries) {
        logm(SL4C_ERROR, "Null, idx=%lx, mask=%lx, key_size=%u\n", idx, mask, map->key_size);
        return NULL;
    }
    if (map->type == UBPF_MAP_TYPE_ARRAY_OF_MAPS)
        ret = *(uintptr_t*)((uint64_t)map->data + idx * map->value_size);
    else
        return (void *)((uint64_t)map->data + idx * map->value_size);

    return (void *)(ret);
}

static int
ubpf_array_update(struct ubpf_map *map, const void *key, void *value)
{
    uint64_t idx = *((const uint64_t *)key);
    if (idx >= map->max_entries) {
        return -5;
    }
    void *addr = (void *)((uint64_t)map->data + map->value_size * idx);
    memcpy(addr, value, map->value_size);
    return 0;
}
