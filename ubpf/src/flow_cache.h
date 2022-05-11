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

#ifndef UBPF_FLOW_CACHE_H
#define UBPF_FLOW_CACHE_H

#include "uthash.h"
#include "ubpf.h"

#define CACHE_SIZE 8
#define HASH_SIZE 1<<20

struct cache_entry {
  u_char *key;
  size_t key_len;
  struct map_context *ctx;
  struct cache_entry *prev, *next;
  UT_hash_handle hh;
};

struct cache_queue {
  unsigned int count;
  unsigned int nb_frames;
  struct cache_entry *front, *rear;
};

enum cache_result {
  NOT_IN_HASH = 0,
  NOT_IN_CACHE,
  NOT_IN_CACHE_FRONT,
  IN_CACHE_FRONT
};

enum cache_result
reference_cache(struct cache_queue *cache,
                struct cache_entry **flows,
                u_char *key, size_t key_len,
                struct cache_entry **out);

struct cache_queue *
create_cache(unsigned int size);


#endif //UBPF_FLOW_CACHE_H
