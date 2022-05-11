/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pcap.h>

#include "cJSON.h"

#include "ubpf.h"
#include "ubpf_hashmap.h"
#include "ubpf_array.c"
#include "match_unit.h"
#include "flow_cache.h"
#include "helper_functions.h"
#include "inc/sclog4c.h"
#include "ubpf_lpm.h"


#define PKT_TOTAL_LEN 1642  // headroom (64) + 1514 + tailroom (64)

void ubpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static inline void
init_output_pcap (FILE **fp, const char *filename);
static inline void
write_pkt(const u_char *pkt_ptr, size_t len, FILE *fp);

static const unsigned char udp_pkt[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3c, 0xec, 0xef, 0x0c, 0xde, 0x60, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xa9, 0x9e, 0x08, 0x08,
        0x08, 0x08, 0xc0, 0xa8, 0x00, 0x64, 0x19, 0x49, 0x04, 0x49, 0x00, 0x1e, 0xb4, 0x9b,
        0x73, 0x75, 0x62, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x75, 0x62, 0x73, 0x70, 0x61,
        0x63, 0x65, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58
};

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

const pcap_hdr_t pcap_global_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 0xffff,
        .network = 0x0001
};

pcaprec_hdr_t pcaprec_hdr = {0};


static void usage(const char *name)
{
    printf("usage: %s [-h] [-j|--jit] [-M|--maps MAP_FILE] [-p|--pcap PATH]"
                    " [-m|--mat MAT_FILE] [-o|--out-stats OUT_FILE] [-O] BINARY\n", name);
    printf( "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    printf("If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    printf("\nIf --pcap is given then the specified trace will be read and the ubpf \nprogram is "
                    "executed for each packet in the trace\n");
    printf("\nIf --maps is given then the specified file will be read and the encoded\nmaps will "
                    "be created in the ubpf VM\n");
    printf("\nOther options:\n");
    printf("  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
    printf("  -O, Write packets out in different files for each return XDP code\n");
}

static void
configure_map_entries(const char *filename, struct ubpf_vm *vm) {
    cJSON *json = NULL;
    FILE *jfile;
    long jsize;
    char *json_str;

    jfile = fopen(filename, "r");
    fseek(jfile, 0, SEEK_END);
    jsize = ftell(jfile);
    rewind(jfile);

    json_str = malloc(jsize + 1);
    fread(json_str, 1, jsize, jfile);

    fclose(jfile);

    json = cJSON_ParseWithLength(json_str, jsize);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
            logm(SL4C_ERROR, "Error before: %s\n", error_ptr);
    }

    if (!cJSON_IsArray(json)) {
        logm(SL4C_ERROR, "Root JSON object not an array\n");
    }

    cJSON *je, *jentries = json;

    cJSON_ArrayForEach(je, jentries) {
        cJSON *jmap_id, *jkey, *jvalue, *jcomment = NULL;

        size_t map_id;
        char *key, *value, *comment = NULL, *ktok, *vtok;
        int ki = 0, vi = 0;

        jmap_id = cJSON_GetObjectItemCaseSensitive(je, "map_id");

        jkey = cJSON_GetObjectItemCaseSensitive(je, "key");
        jvalue = cJSON_GetObjectItemCaseSensitive(je, "value");
        jcomment = cJSON_GetObjectItemCaseSensitive(je, "comment");

        map_id = (size_t) jmap_id->valueint;

        value = jvalue->valuestring;
        key = jkey->valuestring;
        if (jcomment)
            comment = jcomment->valuestring;

        ktok = strtok(key, " ");
        uint8_t out_key[512] = {0};

        while (ktok) {
            out_key[ki] = (uint8_t) strtol(ktok, NULL, 16);
            ktok = strtok(NULL, " ");
            ki++;
        }

        vtok = strtok(value, " ");
        uint8_t out_value[512] = {0};

        while (vtok) {
            out_value[vi] = (uint8_t) strtol(vtok, NULL, 16);
            vtok = strtok(NULL, " ");
            vi++;
        }

        if (comment) {
            if (strncmp(comment, "array_of_maps", 13) == 0) {
                uintptr_t map_ptr = (uintptr_t) vm->ext_maps[out_value[0]];
                char value[8] = {0};

                *(uintptr_t *)value = map_ptr;

                vm->ext_maps[map_id]->ops.map_update(vm->ext_maps[map_id], out_key, (void *)value);
                logm(SL4C_DEBUG, "Configuring array of maps with %lx", map_ptr);
            } else {
                vm->ext_maps[map_id]->ops.map_update(vm->ext_maps[map_id], out_key, out_value);
            }
        } else {
            vm->ext_maps[map_id]->ops.map_update(vm->ext_maps[map_id], out_key, out_value);
        }
    }
}

static int
parse_prog_maps(const char *json_filename, struct ubpf_vm *vm, void *code)
{
    /*
     * Maps parsing from json
     */
    cJSON *json = NULL;
    FILE *jfile;
    long jsize;
    char *json_str;

    jfile = fopen(json_filename, "r");
    fseek(jfile, 0, SEEK_END);
    jsize = ftell(jfile);
    rewind(jfile);

    json_str = malloc(jsize + 1);
    fread(json_str, 1, jsize, jfile);

    fclose(jfile);

    json = cJSON_ParseWithLength(json_str, jsize);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
            logm(SL4C_ERROR, "Error before: %s\n", error_ptr);
        return -1;
    }

    if (!cJSON_IsArray(json)) {
        logm(SL4C_ERROR, "Root JSON object not an array\n");
        return -1;
    }

    cJSON *jmap, *jmaps = json;

    cJSON_ArrayForEach(jmap, jmaps) {
        size_t nb_offsets = 0;
        unsigned int offset[64], type, key_size, value_size, max_entries;
        struct ubpf_map *map;
        const char *sym_name;

        cJSON *jtype = cJSON_GetObjectItemCaseSensitive(jmap, "type");
        cJSON *jkey_size = cJSON_GetObjectItemCaseSensitive(jmap, "key_size");
        cJSON *jvalue_size = cJSON_GetObjectItemCaseSensitive(jmap, "value_size");
        cJSON *jmax_entries = cJSON_GetObjectItemCaseSensitive(jmap, "max_entries");

        type = (unsigned int) cJSON_GetNumberValue(jtype);
        key_size = (unsigned int) cJSON_GetNumberValue(jkey_size);
        value_size = (unsigned int) cJSON_GetNumberValue(jvalue_size);
        max_entries = (unsigned int) cJSON_GetNumberValue(jmax_entries);

        cJSON *joff, *joffsets = cJSON_GetObjectItemCaseSensitive(jmap, "offsets");

        cJSON_ArrayForEach(joff, joffsets) {
            offset[nb_offsets] = (unsigned int) cJSON_GetNumberValue(joff);
            nb_offsets++;
        }

        map = malloc(sizeof(struct ubpf_map));

        map->type = type;
        map->key_size = key_size;
        map->value_size = value_size;
        map->max_entries = max_entries;

        switch (map->type) {
            case UBPF_MAP_TYPE_DEVMAP:  // device map array
            case UBPF_MAP_TYPE_PER_CPU_ARRAY:  // per cpu array
            case UBPF_MAP_TYPE_ARRAY:
                map->ops = ubpf_array_ops;
                map->data = ubpf_array_create(map);
                sym_name = "arraymap";
                break;
            case UBPF_MAP_TYPE_PER_CPU_HASHMAP:  // per cpu hash
            case UBPF_MAP_TYPE_PER_CPU_LRU_HASH:
            case UBPF_MAP_TYPE_HASHMAP:
                map->ops = ubpf_hashmap_ops;
                map->data = ubpf_hashmap_create(map);
                sym_name = "hashmap";
                break;
            case UBPF_MAP_TYPE_LPM_TRIE:
                map->ops = ubpf_lpm_ops;
                map->data = ubpf_lpm_create(map);
                sym_name = "lpmmap";
                break;
            case UBPF_MAP_TYPE_ARRAY_OF_MAPS:
                map->ops = ubpf_array_ops;
                if (map->value_size < 8)
                    map->value_size = 8;
                map->data = ubpf_array_create(map);
                break;
            default:
                logm(SL4C_ERROR, "unrecognized map type: %d", map->type);
                free(map);
                return 1;
        }

        int result = ubpf_register_map(vm, sym_name, map);
        if (result == -1) {
            logm(SL4C_ERROR, "failed to register variable '%s'", sym_name);
            free(map);
            return 1;
        }

        if (nb_offsets != 0) {
            for (int i = 0; i < nb_offsets; i++) {
                *(uint32_t *) ((uint64_t) code + offset[i] * 8 + 4) = (uint32_t) ((uint64_t) map);
                *(uint32_t *) ((uint64_t) code + offset[i] * 8 + sizeof(struct ebpf_inst) + 4) =
                        (uint32_t) ((uint64_t) map >> 32);
            }
        }

        logm(SL4C_DEBUG, "map: %lx, # entries: %d\n", (uint64_t) map, map->max_entries);
    }

    free(json_str);

    return 0;
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "mat", .val = 'm', .has_arg=1 },
        { .name = "maps", .val = 'M', .has_arg=1},
        { .name = "pcap", .val = 'p', .has_arg=1},
        { .name = "entries-map", .val = 'e', .has_arg=1},
        { .name = "out-stats", .val = 'o', .has_arg=1},
        { .name = "out-pcaps", .val = 'O', },
        { .name = "log-level", .val = 'l', .has_arg=1},
        { }
    };

    const char *mat_filename = NULL;
    const char *json_filename = NULL;
    const char *pcap_filename = NULL;
    const char *out_filename = NULL;
    const char *map_entries_filename = NULL;
    int log_level = 0;
    bool out_pcaps = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:p:M:e:o:Ol:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mat_filename = optarg;
            break;
        case 'M':
            json_filename = optarg;
            break;
        case 'p':
            pcap_filename = optarg;
            break;
        case 'e':
            map_entries_filename = optarg;
            break;
        case 'l':
            log_level = atoi(optarg);
            break;
        case 'o':
            out_filename = optarg;
            break;
        case 'O':
            out_pcaps = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    switch (log_level) {
        case 1:
            sclog4c_level = SL4C_INFO;
            break;
        case 2:
            sclog4c_level = SL4C_DEBUG;
            break;
        case 3:
            sclog4c_level = SL4C_ALL;
            break;
        default:
            sclog4c_level = SL4C_ERROR;
    }

    const char *code_filename = argv[optind];
    size_t code_len;
    void *code = readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    (void) *udp_pkt;

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        logm(SL4C_ERROR, "Failed to create VM");
        return 1;
    }

    register_functions(vm);

    uint64_t ret;

    if (json_filename) {
        ret = parse_prog_maps(json_filename, vm, code);
        if (ret != 0) {
            logm(SL4C_ERROR, "Error in parsing maps and bpf code");
            ubpf_destroy(vm);
            return ret;
        }
    }

    /*
     * Load program
     */
    char *errmsg;
    int rv;

    rv = ubpf_load(vm, code, code_len, &errmsg);

    free(code);

    if (rv < 0) {
        logm(SL4C_ERROR, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    /*
     * Parse the json of the map entries to load in the maps, if any
     */
    if (map_entries_filename) {
        configure_map_entries(map_entries_filename, vm);
    }

    /*
     * Parse the json of the MAT if any
     */
    struct match_table *mat = NULL;

    if(mat_filename) {
        FILE *mat_file;
        size_t mat_size;
        char *mat_string;

        mat_file = fopen(mat_filename, "r");
        fseek(mat_file, 0, SEEK_END);
        mat_size = ftell(mat_file);
        rewind(mat_file);

        mat_string = malloc(mat_size + 1);
        fread(mat_string, 1, mat_size, mat_file);

        fclose(mat_file);

        mat = malloc(sizeof(struct match_table));

        if (parse_mat_json(mat_string, mat_size, mat) < 0){
            logm(SL4C_ERROR, "error in parsing MAT");
            free(mat);
            free(mat_string);
            return -1;
        }
        free(mat_string);
    }

    /*
     * Pcap trace parsing and main processing loop
     */
    if (pcap_filename) {
        pcap_t *p;
        char errbuf[PCAP_ERRBUF_SIZE];
        const u_char *pkt_ptr_pcap;
        u_char *pkt_buf, *pkt_data;
        struct pcap_pkthdr *hdr;
        FILE *out_pass, *out_drop, *out_tx, *out_redirect;
        int npkts = 1;
        struct xdp_md xdp_md = {0};

        p = pcap_open_offline(pcap_filename, errbuf);

        if (p == NULL) {
            logm(SL4C_ERROR, "pcap_open_offline failed: %s", errbuf);
            return -1;
        }

        if (out_pcaps) {
            out_pass = out_drop = out_tx = out_redirect = NULL;
            // Init the output pcap with the pcap header
            init_output_pcap(&out_pass, "pass.pcap");
            init_output_pcap(&out_drop, "drop.pcap");
            init_output_pcap(&out_tx, "tx.pcap");
            init_output_pcap(&out_redirect, "redirect.pcap");
        }

        // allocate packet memory with headroom and tailroom
        pkt_buf = malloc(PKT_TOTAL_LEN);
        // set pointer to packet data discarding headroom
        pkt_data = pkt_buf + PKT_HEADROOM;

        /*
         * Execute the program for each packet
         */
        while (pcap_next_ex(p, &hdr, &pkt_ptr_pcap) > 0) {
            struct pkt_field *extracted_fields;
            struct action_entry *act = NULL;
            size_t new_pkt_len;

            memcpy(pkt_data, pkt_ptr_pcap, hdr->caplen);
            xdp_md.data = (uintptr_t) pkt_data;
            xdp_md.data_end = (uintptr_t) (pkt_data + hdr->caplen);

            logm(SL4C_INFO, "Packet #%d", npkts);

            if (mat) {
                extracted_fields = parse_pkt_header(pkt_data, mat);

                dump_fields(extracted_fields, mat->entries[0].nb_pkt_fields);

                act = lookup_entry(mat, extracted_fields);

                if (act) {
                    if (act->op == MAP_ACCESS) {
                        ret = ubpf_exec(vm, &xdp_md, act->reg_def, &act->stack_def, act->pc, act->map_id);
                    } else if (act->op == ABANDON) {  // usual standard processing
                        ret = ubpf_exec(vm, &xdp_md, NULL, NULL, 0, 0);
                    } else {
                        logm(SL4C_WARNING, "Instructions count: 0");
                        ret = act->op;
                    }
                } else { //No ACT
                    logm(SL4C_WARNING, "Match not found in lookup entry");
                }
            } else {  // no MAT, standard processing
                ret = ubpf_exec(vm, &xdp_md, NULL, NULL, 0, 0);
            }

            // Update the packet length, that could have been modified in the program
            new_pkt_len = xdp_md.data_end - xdp_md.data;

            if (out_pcaps) {
                switch (ret) {
                    case XDP_ABORTED:
                    case XDP_DROP:
                        write_pkt((u_char *) xdp_md.data, new_pkt_len, out_drop);
                        break;
                    case XDP_PASS:
                        write_pkt((u_char *) xdp_md.data, new_pkt_len, out_pass);
                        break;
                    case XDP_TX:
                        write_pkt((u_char *) xdp_md.data, new_pkt_len, out_tx);
                        break;
                    case XDP_REDIRECT:
                        write_pkt((u_char *) xdp_md.data, new_pkt_len, out_redirect);
                        break;
                    case ABANDON:
                    case MAP_ACCESS:
                        logm(SL4C_ERROR, "This action here is illegal");
                        break;
                    default:
                        logm(SL4C_ERROR, "XDP return code unknown");
                        break;
                }
            }

            logm(SL4C_INFO, "return 0x%"PRIx64"\n", ret);
            npkts++;
        }

        if (out_pcaps) {
            fclose(out_pass);
            fclose(out_drop);
            fclose(out_tx);
            fclose(out_redirect);
        }

        free(pkt_buf);

        if (out_filename) {
            FILE *out_stats;
            int i;

            out_stats = fopen(out_filename, "w");

            for (i=0; i<mat->nb_entries; i++)
                fprintf(out_stats, "%d,%lu\n", i, mat->entries[i].cnt);

            fclose(out_stats);
        }
    }

    ubpf_destroy(vm);

    return 0;
}


static void
init_output_pcap (FILE **fp, const char *filename) {
    *fp = fopen(filename, "wb");
    fwrite(&pcap_global_hdr, 1, sizeof(pcap_hdr_t), *fp);

    if(!*fp) {
        logm(SL4C_ERROR, "Error cannot open %s", filename);
        exit(-1);
    }
}

static void
write_pkt(const u_char *pkt_ptr, size_t len, FILE *fp) {
    // update length of the packet
    pcaprec_hdr.incl_len = len;
    pcaprec_hdr.orig_len = len;

    // write packet to output file
    fwrite(&pcaprec_hdr, 1, sizeof(pcaprec_hdr_t), fp);
    fwrite(pkt_ptr, 1, len, fp);
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        logm(SL4C_ERROR, "Failed to open %s: %s", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        logm(SL4C_ERROR, "Failed to read %s: %s", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        logm(SL4C_ERROR, "Failed to read %s because it is too large (max %u bytes)",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}