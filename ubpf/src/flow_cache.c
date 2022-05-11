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

#include <stdbool.h>
#include "flow_cache.h"
#include "ubpf_int.h"
#include "inc/sclog4c.h"

static inline void
dump_hashtable(struct cache_entry *flows) {
    struct cache_entry *element, *tmp;
    logm(SL4C_DEBUG, "Dumping hashtable");
    if (sclog4c_level <= SL4C_DEBUG) {
        HASH_ITER(hh, flows, element, tmp) {
            for (int i=0; i<element->key_len; i++) {
                fprintf(stderr,"%02x", element->key[i]);
            }

            fprintf(stderr," hash value: 0x%08x", element->hh.hashv);

            fprintf(stderr, "\n");
        }
    }
}

static inline struct cache_entry *
add_cache_entry_to_hash(struct cache_entry** flows,
                    u_char *in_key, size_t key_len)
{
    struct cache_entry *cache_entry = malloc(sizeof(struct cache_entry));
    cache_entry->ctx = malloc(sizeof(struct map_context));
    cache_entry->key = malloc(key_len);

    cache_entry->key_len = key_len;

    memcpy(cache_entry->key, in_key, key_len);

    cache_entry->prev = NULL;
    cache_entry->next = NULL;

    if (sclog4c_level <= SL4C_DEBUG) {
        logm(SL4C_DEBUG, "Adding a new key to the hash, key len is %lu\n", key_len);

        for (int i=0; i<cache_entry->key_len; i++) {
            fprintf(stderr,"%02x", cache_entry->key[i]);
        }
        fprintf(stderr, "\n\n");
    }

    HASH_ADD_KEYPTR(hh, *flows, cache_entry->key, key_len, cache_entry);

    dump_hashtable(*flows);

    return cache_entry;
}

static inline struct cache_entry *
find_cache_entry_in_hash(struct cache_entry *flows, u_char *in_key, size_t key_len)
{
    struct cache_entry *found = NULL;

    if (sclog4c_level <= SL4C_DEBUG) {
        logm(SL4C_DEBUG, "FINDING cache entry in the hash\n------->");

        for (int i=0; i<key_len; i++) {
            fprintf(stderr,"%02x", in_key[i]);
        }
        fprintf(stderr, "\n\n");
    }

    HASH_FIND(hh, flows, in_key, key_len, found);

    if (found)
        return found;
    else
        return NULL;
}

bool
cache_empty(struct cache_queue *cache)
{
    if (cache->count == 0)
        return true;
    else
        return false;
}

bool
cache_full(struct cache_queue *cache)
{
    if (cache->count == cache->nb_frames)
        return true;
    else
        return false;
}

void
dequeue(struct cache_queue *cache)
{
    if (cache_empty(cache))
        return;

    if (cache->front == cache->rear)
        cache->front = NULL;

    struct cache_entry *tmp = cache->rear;
    cache->rear = cache->rear->prev;

    if (cache->rear)
        cache->rear->next = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    cache->count--;
}

void
enqueue(struct cache_queue *cache, struct cache_entry *req_entry)
{
    if (cache_full(cache)) {
        dequeue(cache);
    }

    req_entry->next = cache->front;

    if (cache_empty(cache)) {
        cache->rear = cache->front = req_entry;
    } else {
        cache->front->prev = req_entry;
        cache->front = req_entry;
    }

    cache->count++;
}

enum cache_result
reference_cache(struct cache_queue *cache,
                    struct cache_entry **flows,
                    u_char *key, size_t key_len,
                    struct cache_entry **out)
{
    struct cache_entry *req_entry = NULL;

    req_entry = find_cache_entry_in_hash(*flows, key, key_len);

    *out = req_entry;

    // If requested entry is not in hash
    if (!req_entry) {
        req_entry = add_cache_entry_to_hash(flows, key, key_len);

        *out = req_entry;

        enqueue(cache, req_entry);

        return NOT_IN_HASH;
    }
    // If req_entry is not in the cache
    else if (req_entry->prev == NULL && req_entry->next == NULL && cache->front != req_entry) {
        dequeue(cache);

        enqueue(cache, req_entry);

        return NOT_IN_CACHE;
    }
    // if requested entry is in cache but not at front
    else if (req_entry != cache->front) {
        // Unlink requested entry
        req_entry->prev->next = req_entry->next;
        if (req_entry->next)
            req_entry->next->prev = req_entry->prev;

        if (req_entry == cache->rear) {
            cache->rear = req_entry->prev;
            cache->rear->next = NULL;
        }

        req_entry->next = cache->front;
        req_entry->prev = NULL;

        req_entry->next->prev = req_entry;

        cache->front = req_entry;

        return NOT_IN_CACHE_FRONT;
    } else {  // Requested entry is in cache at first position
        return IN_CACHE_FRONT;
    }
}

struct cache_queue *
create_cache(unsigned int size)
{
    struct cache_queue *cache = malloc(sizeof(struct cache_queue));

    cache->count = 0;
    cache->front = cache->rear = NULL;

    cache->nb_frames = size;

    return cache;
}