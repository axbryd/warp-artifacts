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

#include <sclog4c.h>
#include "ubpf_lpm.h"
#include "uthash.h"

static inline void
lpm_apply_mask(uint32_t key_size, uint32_t prefix, uint32_t **val)
{
    uint32_t *out = (uint32_t *)val;

    switch (key_size) {
        // IPv4 addresses
        case 8:
            out[0] &= (uint32_t) (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
            break;
            // IPv6 addresses
        case 20:
            if (prefix > 128)
                break;
            if (prefix >= 96 && prefix < 128) {
                out[3] &= (uint32_t) (0xFFFFFFFF << (32 - prefix%32)) & 0xFFFFFFFF;
                out[0] = out[1] = out[2] = 0;
            } else if (prefix >= 64 && prefix < 96) {
                out[2] &= (uint32_t) (0xFFFFFFFF << (32 - prefix%32)) & 0xFFFFFFFF;
                out[0] = out[1] = 0;
            } else if (prefix >= 32 && prefix < 64) {
                out[1] &= (uint32_t) (0xFFFFFFFF << (32 - prefix%32)) & 0xFFFFFFFF;
                out[0]= 0;
            } else {
                out[0] &= (uint32_t) (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
            }
            break;
        default:
            logm(SL4C_ERROR, "Key size %d not supported", key_size);
            break;
    }
}

void *
ubpf_lpm_create(const struct ubpf_map *map)
{
    uint8_t prefix_len;
    struct ubpf_lpm *lpm = malloc(sizeof(struct ubpf_lpm));

    switch (map->key_size) {
        // IPv4 addresses
        case 8:
            prefix_len = 32;
            break;
        // IPv6 addresses
        case 20:
            prefix_len = 128;
            break;
        default:
            logm(SL4C_ERROR, "Key size %d not supported", map->key_size);
            return NULL;
    }

    lpm->lpm_size = prefix_len;
    lpm->count = 0;
    lpm->lpm_hmaps = malloc(prefix_len * sizeof(struct lpm_hmap *));
    for (int i=0; i<lpm->lpm_size; i++)
        lpm->lpm_hmaps[i] = NULL;

    return lpm;
}

unsigned int
ubpf_lpm_size(const struct ubpf_map *map)
{
    struct ubpf_lpm *lpm = (struct ubpf_lpm *) map->data;
    return lpm->count;
}

void *
ubpf_lpm_lookup(const struct ubpf_map *map, const void *key)
{
    struct ubpf_lpm *lpm = (struct ubpf_lpm *) map->data;
    uint32_t masked_key[4] = {0};

    memcpy(masked_key, key+4, map->key_size-4);

    masked_key[0] = be32toh(masked_key[0]);
    masked_key[1] = be32toh(masked_key[1]);
    masked_key[2] = be32toh(masked_key[2]);
    masked_key[3] = be32toh(masked_key[3]);

    for (int i=lpm->lpm_size-1; i>-1; i--) {
        struct lpm_hmap *elem = NULL;

        lpm_apply_mask(map->key_size, i+1, (uint32_t **) &masked_key);

        HASH_FIND(hh, lpm->lpm_hmaps[i],
                  masked_key, map->key_size - 4, elem);
        if (elem)
            return elem->value;
    }
    return NULL;
}

int
ubpf_lpm_update(struct ubpf_map *map, const void *key, void *value)
{
    struct ubpf_lpm *lpm = map->data;
    struct lpm_hmap *old_elem = NULL;

    old_elem = ubpf_lpm_lookup(map, key);

    if (!old_elem && (lpm->count >= map->max_entries)) {
        return -4;
    }

    if (old_elem) {
        memcpy(old_elem->value, value, map->value_size);
    } else {
        struct lpm_hmap *new_elem;
        struct lpm_hmap **head;
        uint32_t prefix = be32toh(*(uint32_t *)key);

        new_elem = malloc(sizeof(struct lpm_hmap));
        memcpy(new_elem->key, key+4, map->key_size);

        new_elem->key[0] = be32toh(new_elem->key[0]);
        new_elem->key[1] = be32toh(new_elem->key[1]);
        new_elem->key[2] = be32toh(new_elem->key[2]);
        new_elem->key[3] = be32toh(new_elem->key[3]);

        lpm_apply_mask(map->key_size, prefix, (uint32_t **) &new_elem->key);

        new_elem->value = malloc(map->value_size);
        memcpy(new_elem->value, value, map->value_size);

        head = &lpm->lpm_hmaps[prefix - 1];

        HASH_ADD(hh, *head, key, map->key_size - 4, new_elem);

        lpm->count++;
    }

    return 0;
}

int
ubpf_lpm_delete(struct ubpf_map *map, const void *key)
{
    struct ubpf_lpm *lpm = map->data;
    struct lpm_hmap *elem = NULL;
    int position;

    for (int i=lpm->lpm_size - 1; i>-1; i--) {
        HASH_FIND(hh, lpm->lpm_hmaps[i],
                  key+4, map->key_size - 4, elem);
        if (elem) {
            position = i;
            break;
        }
    }

    if (!elem)
        return -4;

    HASH_DEL(lpm->lpm_hmaps[position], elem);

    free(elem->value);
    free(elem);

    return 0;
}

unsigned int
ubpf_lpm_dump(const struct ubpf_map *map, void *data)
{
    struct ubpf_lpm *lpm = map->data;
    (void)data;
    return lpm->count;
}



