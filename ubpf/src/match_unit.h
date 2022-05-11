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

#ifndef UBPF_MATCH_UNIT_H
#define UBPF_MATCH_UNIT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "cJSON.h"

#define round_up_to_8(x) ((x+7) & (-8))
#define MAX_OPS 8

enum alu_ops {
  ALU_OPS_NULL,
  ALU_OPS_LE,
  ALU_OPS_BE,
  ALU_OPS_AND,
  ALU_OPS_OR,
  ALU_OPS_LSH,
  ALU_OPS_RSH,
  ALU_OPS_ADD,
};

enum reg_def_ops {
  REG_DEF_NULL,
  REG_DEF_IMM,
  REG_DEF_STACK_PTR,
  REG_DEF_PKT_PTR,
  REG_DEF_PKT_FLD,
  REG_DEF_PKT_END,
  REG_DEF_CTX_PTR,
};

struct pkt_field_def {
  uint16_t offset;  // in bytes
  uint8_t len;      // in bits
  enum alu_ops op[MAX_OPS];
  uint8_t nb_ops;
  uint64_t imm[MAX_OPS];
};

struct pkt_field {
  void *value;
  bool dontcare;
};

enum action_ops {
  XDP_ABORTED = 0,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT,
  MAP_ACCESS,
  ABANDON
};

struct key_field {
  int kstart;
  int kend;
  uint64_t imm;
  bool has_imm;
  enum reg_def_ops type;
  struct pkt_field_def pkt_fld;
};

struct reg_def {
    uint64_t val;
    int offset;
    uint8_t len;
    enum reg_def_ops type;
    struct pkt_field_def pkt_fld;
};

struct stack_def {
    uint8_t nb_fields;
    struct key_field *key_fields;
};

struct action_entry {
    enum action_ops op;
    uint8_t map_id;
    uint16_t pc;
    struct reg_def reg_def[11];
    struct stack_def stack_def;
};

struct match_entry {
  struct pkt_field *fields;
  struct action_entry *act;
  uint8_t nb_pkt_fields;
  uint64_t cnt;
};

struct match_table {
  struct match_entry *entries;
  uint8_t nb_entries;
  struct pkt_field_def *field_defs;
};

struct action_entry *
lookup_entry(struct match_table *mat, struct pkt_field *parsed_fields);

int
parse_mat_json(const char *jstring, size_t buf_len, struct match_table *mat);

struct pkt_field *
parse_pkt_header(const u_char *pkt, struct match_table *mat);

void
dump_fields(struct pkt_field *parsed_fields, uint8_t nb_fields);

//u_char *
//generate_key(struct action_entry *act, const u_char *pkt, size_t *key_len);

int
parse_context(struct action_entry *act, const cJSON *context);

uint64_t
field_manipulation(enum alu_ops op, uint64_t imm,
                   uint64_t value, uint8_t fld_len_in_bytes);


#endif //UBPF_MATCH_UNIT_H
