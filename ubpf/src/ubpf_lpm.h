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

#ifndef UBPF_UBPF_LPM_H
#define UBPF_UBPF_LPM_H

#include "ubpf_int.h"
#include "uthash.h"

void *ubpf_lpm_create(const struct ubpf_map *map);
unsigned int ubpf_lpm_size(const struct ubpf_map *map);
unsigned int ubpf_lpm_dump(const struct ubpf_map *map, void *data);
void *ubpf_lpm_lookup(const struct ubpf_map *map, const void *key);
int ubpf_lpm_update(struct ubpf_map *map, const void *key, void *value);
int ubpf_lpm_delete(struct ubpf_map *map, const void *key);

struct lpm_hmap {
  UT_hash_handle hh;
  uint32_t key[4];
  void *value;
};

typedef struct ubpf_lpm {
  struct lpm_hmap **lpm_hmaps;  // array of hashmaps
  uint8_t lpm_size;
  unsigned int count;
} ubpf_lpm_t;

static const struct ubpf_map_ops ubpf_lpm_ops = {
        .map_size = ubpf_lpm_size,
        .map_dump = ubpf_lpm_dump,
        .map_lookup = ubpf_lpm_lookup,
        .map_update = ubpf_lpm_update,
        .map_delete = ubpf_lpm_delete,
        .map_add = NULL,
};

#endif //UBPF_UBPF_LPM_H
