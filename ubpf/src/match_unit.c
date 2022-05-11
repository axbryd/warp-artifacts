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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"

#include "match_unit.h"
#include "inc/sclog4c.h"

int
parse_context(struct action_entry *act, const cJSON *context) {
    const cJSON *registers = NULL, *stack = NULL;
    const cJSON *r, *s;
    int i, j = 0;
    int nb_stack_fields;
    char num[3];
    struct reg_def *rdef;

    registers = cJSON_GetObjectItemCaseSensitive(context, "registers");

    for (i = 0; i <= 10; i++) {
        sprintf(num,"%d", i);
        r = cJSON_GetObjectItemCaseSensitive(registers, num);

        if (r) {
            const cJSON *rtype = cJSON_GetObjectItemCaseSensitive(r, "type");
            rdef = &act->reg_def[i];

            if (strcmp(rtype->valuestring, "Immediate") == 0) {
                const cJSON *rval = cJSON_GetObjectItemCaseSensitive(r, "val");

                rdef->type = REG_DEF_IMM;
                rdef->val = rval->valueint;
            } else if (strcmp(rtype->valuestring, "StackPointer") == 0) {
                const cJSON *roffset = cJSON_GetObjectItemCaseSensitive(r, "offset");

                rdef->type = REG_DEF_STACK_PTR;
                rdef->offset = roffset->valueint;
            } else if (strcmp(rtype->valuestring, "PacketPointer") == 0) {
                const cJSON *roffset = cJSON_GetObjectItemCaseSensitive(r, "offset");

                rdef->type = REG_DEF_PKT_PTR;
                rdef->offset = roffset->valueint;
            } else if (strcmp(rtype->valuestring, "PacketEnd") == 0) {
                rdef->type = REG_DEF_PKT_END;
            } else if (strcmp(rtype->valuestring, "ContextPointer") == 0) {
                rdef->type = REG_DEF_CTX_PTR;
            } else if (strcmp(rtype->valuestring, "PacketField") == 0) {
                const cJSON *offset, *len, *fld_manipulations = NULL;

                offset = cJSON_GetObjectItemCaseSensitive(r, "offset");
                len = cJSON_GetObjectItemCaseSensitive(r, "len");
                fld_manipulations = cJSON_GetObjectItemCaseSensitive(r, "field_manipulations");

                rdef->type = REG_DEF_PKT_FLD;

                // Process field manipulations if any
                if (cJSON_GetArraySize(fld_manipulations) > 0) {
                    const cJSON *fld_alu_op = NULL;
                    const cJSON *fld_immediate = NULL;
                    const cJSON *fld_man = NULL;
                    unsigned int nb_ops = 0;

                    cJSON_ArrayForEach(fld_man, fld_manipulations) {
                        fld_alu_op = cJSON_GetObjectItemCaseSensitive(fld_man, "alu_op");
                        fld_immediate = cJSON_GetObjectItemCaseSensitive(fld_man, "immediate");

                        if (strcmp(fld_alu_op->valuestring, "AluOps.le") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_LE;
                            rdef->pkt_fld.imm[nb_ops] = 0;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.be") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_BE;
                            rdef->pkt_fld.imm[nb_ops] = 0;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.bit_and") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_AND;
                            rdef->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.bit_or") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_OR;
                            rdef->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.lsh") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_LSH;
                            rdef->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.rsh") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_RSH;
                            rdef->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.add") == 0) {
                            rdef->pkt_fld.op[nb_ops] = ALU_OPS_ADD;
                            rdef->pkt_fld.imm[nb_ops] = (uint64_t) fld_immediate->valueint;
                        } else {
                            logm(SL4C_ERROR, "ALU operation not supported\n");
                            return -1;
                        }
                        nb_ops++;
                    }
                    rdef->pkt_fld.nb_ops = nb_ops;
                } else {  // no packet field manipulations
                    rdef->pkt_fld.op[0] = ALU_OPS_NULL;
                    rdef->pkt_fld.nb_ops = 1;
                }
                rdef->pkt_fld.offset = offset->valueint;
                rdef->pkt_fld.len = len->valueint;
            } else {  // Not recognized register type
                logm(SL4C_ERROR, "Not recognized register type \"%s\"\n", rtype->valuestring);
                return -1;
            }
        } else {  // No register restoration at this position
            act->reg_def[i].type = REG_DEF_NULL;
            continue;
        }
    }

    /*
     * Stack definition parsing
     */
    stack = cJSON_GetObjectItemCaseSensitive(context, "stack");

    nb_stack_fields = cJSON_GetArraySize(stack);

    act->stack_def.nb_fields = nb_stack_fields;
    act->stack_def.key_fields = malloc(nb_stack_fields * sizeof(struct key_field));

    cJSON_ArrayForEach(s, stack) {
        const cJSON *start = NULL, *end = NULL, *value_type = NULL;
        const cJSON *fld_type = NULL;

        struct key_field *key_field = &act->stack_def.key_fields[j];

        start = cJSON_GetObjectItemCaseSensitive(s, "start");
        end = cJSON_GetObjectItemCaseSensitive(s, "end");
        value_type = cJSON_GetObjectItemCaseSensitive(s, "value_type");
        fld_type = cJSON_GetObjectItemCaseSensitive(value_type, "type");

        key_field->kstart = start->valueint;
        key_field->kend = end->valueint;

        if (strcmp(fld_type->valuestring, "PacketField") == 0) {
            const cJSON *offset, *len, *fld_manipulations = NULL;

            key_field->type = REG_DEF_PKT_FLD;

            key_field->has_imm = false;

            offset = cJSON_GetObjectItemCaseSensitive(value_type, "offset");
            len = cJSON_GetObjectItemCaseSensitive(value_type, "len");
            fld_manipulations = cJSON_GetObjectItemCaseSensitive(value_type, "field_manipulations");

            key_field->pkt_fld.offset = offset->valueint;
            key_field->pkt_fld.len = len->valueint;

            // Process field manipulations if any
            if (cJSON_GetArraySize(fld_manipulations) > 0) {
                const cJSON *fld_alu_op = NULL;
                const cJSON *fld_immediate = NULL;
                const cJSON *fld_man = NULL;
                unsigned int nb_ops = 0;

                cJSON_ArrayForEach(fld_man, fld_manipulations) {
                    fld_alu_op = cJSON_GetObjectItemCaseSensitive(fld_man, "alu_op");
                    fld_immediate = cJSON_GetObjectItemCaseSensitive(fld_man, "immediate");

                    if (strcmp(fld_alu_op->valuestring, "AluOps.le") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_LE;
                        key_field->pkt_fld.imm[nb_ops] = 0;
                    } else if (strcmp(fld_alu_op->valuestring, "AluOps.be") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_BE;
                        key_field->pkt_fld.imm[nb_ops] = 0;
                    } else if (strcmp(fld_alu_op->valuestring, "AluOps.bit_and") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_AND;
                        key_field->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                    } else if (strcmp(fld_alu_op->valuestring, "AluOps.bit_or") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_OR;
                        key_field->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                    } else if (strcmp(fld_alu_op->valuestring, "AluOps.lsh") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_LSH;
                        key_field->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                    } else if (strcmp(fld_alu_op->valuestring, "AluOps.rsh") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_RSH;
                        key_field->pkt_fld.imm[nb_ops] = fld_immediate->valueint;
                    } else if (strcmp(fld_alu_op->valuestring, "AluOps.add") == 0) {
                        key_field->pkt_fld.op[nb_ops] = ALU_OPS_ADD;
                        key_field->pkt_fld.imm[nb_ops] = (uint64_t) fld_immediate->valueint;
                    } else {
                        logm(SL4C_ERROR, "ALU operation not supported\n");
                        return -1;
                    }
                    nb_ops++;
                }
                key_field->pkt_fld.nb_ops = nb_ops;
            } else {
                key_field->pkt_fld.op[0] = ALU_OPS_NULL;
                key_field->pkt_fld.nb_ops = 1;
                key_field->pkt_fld.imm[0] = 0;
            }
        } else if (strcmp(fld_type->valuestring, "Immediate") == 0) {
            const cJSON *val = NULL;
            key_field->type = REG_DEF_IMM;

            val = cJSON_GetObjectItemCaseSensitive(value_type, "val");

            key_field->imm = val->valueint;
            key_field->has_imm = true;
        } else if (strcmp(fld_type->valuestring, "PacketPointer") == 0) {
            const cJSON *offset = NULL;

            offset = cJSON_GetObjectItemCaseSensitive(value_type, "offset");

            key_field->type = REG_DEF_PKT_PTR;
            key_field->imm = offset->valueint;
            key_field->has_imm = true;
        }  else if (strcmp(fld_type->valuestring, "StackPointer") == 0) {
            const cJSON *offset = NULL;

            offset = cJSON_GetObjectItemCaseSensitive(value_type, "offset");

            key_field->type = REG_DEF_STACK_PTR;
            key_field->imm = offset->valueint;
            key_field->has_imm = true;
        }else {
            logm(SL4C_ERROR, "Action value type not supported \"%s\"\n", fld_type->valuestring);
            return -1;
        }
        j++;
    }

    return 0;
}

int
parse_mat_json(const char *jstring, size_t buf_len, struct match_table *mat)
{
    cJSON *json = NULL;
    const cJSON *entry = NULL, *entries = NULL;
    struct pkt_field_def *pkt_field_defs;

    json = cJSON_ParseWithLength(jstring, buf_len);

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

    entries = json;

    mat->nb_entries = cJSON_GetArraySize(entries);
    mat->entries = malloc(mat->nb_entries * sizeof(struct match_entry));

    int curr_entry = 0;
    /*
     * Loop on all the match entries
     */
    cJSON_ArrayForEach(entry, entries)
    {
        const cJSON *matches = NULL, *field = NULL;
        const cJSON *priority = NULL, *action = NULL;
        int pri, nb_pkt_fields, i = 0;

        matches = cJSON_GetObjectItemCaseSensitive(entry, "matches");
        priority = cJSON_GetObjectItemCaseSensitive(entry, "priority");
        action = cJSON_GetObjectItemCaseSensitive(entry, "action");

        pri = priority->valueint;

        nb_pkt_fields = cJSON_GetArraySize(matches);

        pkt_field_defs = malloc(nb_pkt_fields * sizeof(struct pkt_field_def));
        mat->entries[pri].fields = malloc(nb_pkt_fields * sizeof(struct pkt_field));
        mat->entries[pri].nb_pkt_fields = nb_pkt_fields;
        mat->entries[pri].cnt = 0;

        // Iterate over match fields
        cJSON_ArrayForEach(field, matches) {
            const cJSON *type = NULL, *operand0 = NULL, *operand1 = NULL;

            type = cJSON_GetObjectItemCaseSensitive(field, "type");
            operand0 = cJSON_GetObjectItemCaseSensitive(field, "operand0");

            // Process operand 0
            if (operand0) {
                const cJSON *joffset = NULL, *jlen = NULL;
                const cJSON *jfield_manipulations = NULL;

                joffset = cJSON_GetObjectItemCaseSensitive(operand0, "offset");
                jlen = cJSON_GetObjectItemCaseSensitive(operand0, "len");
                jfield_manipulations =
                        cJSON_GetObjectItemCaseSensitive(operand0,
                                                         "field_manipulations");

                // Process field manipulations if any
                if (cJSON_GetArraySize(jfield_manipulations) > 0) {
                    const cJSON *fld_alu_op = NULL;
                    const cJSON *fld_immediate = NULL;
                    const cJSON *fld_man = NULL;
                    unsigned int nb_ops = 0;

                    cJSON_ArrayForEach(fld_man, jfield_manipulations) {
                        fld_alu_op = cJSON_GetObjectItemCaseSensitive(fld_man, "alu_op");
                        fld_immediate = cJSON_GetObjectItemCaseSensitive(fld_man, "immediate");

                        if (strcmp(fld_alu_op->valuestring, "AluOps.le") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_LE;
                            pkt_field_defs[i].imm[nb_ops] = 0;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.be") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_BE;
                            pkt_field_defs[i].imm[nb_ops] = 0;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.bit_and") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_AND;
                            pkt_field_defs[i].imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.bit_or") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_OR;
                            pkt_field_defs[i].imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.lsh") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_LSH;
                            pkt_field_defs[i].imm[nb_ops] = fld_immediate->valueint;
                        } else if (strcmp(fld_alu_op->valuestring, "AluOps.rsh") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_RSH;
                            pkt_field_defs[i].imm[nb_ops] = fld_immediate->valueint;
                        }  else if (strcmp(fld_alu_op->valuestring, "AluOps.add") == 0) {
                            pkt_field_defs[i].op[nb_ops] = ALU_OPS_ADD;
                            pkt_field_defs[i].imm[nb_ops] = (uint64_t) fld_immediate->valueint;
                        }else {
                            logm(SL4C_ERROR, "ALU operation not supported\n");
                            return -1;
                        }
                        nb_ops++;
                    }
                    pkt_field_defs[i].nb_ops = nb_ops;
                } else {
                    pkt_field_defs[i].op[0] = ALU_OPS_NULL;
                    pkt_field_defs[i].nb_ops = 1;
                    pkt_field_defs[i].imm[0] = 0;
                }

                pkt_field_defs[i].offset = joffset->valueint;
                pkt_field_defs[i].len = jlen->valueint;

            } else {  // No operand 0
                logm(SL4C_ERROR, "No operand 0\n");
                return -1;
            }

            struct pkt_field *fld = &mat->entries[pri].fields[i];

            // DontCare processing
            // If the type of the entry is don't care we don't need operand1
            if (strncmp(type->valuestring, "DontCare", sizeof("DontCare")) == 0) {
                fld->value = NULL;
                fld->dontcare = true;
            } else {
                // Operand 1 processing
                const cJSON *val = NULL, *op1_type = NULL;

                operand1 = cJSON_GetObjectItemCaseSensitive(field, "operand1");

                val = cJSON_GetObjectItemCaseSensitive(operand1, "val");
                op1_type = cJSON_GetObjectItemCaseSensitive(operand1, "type");

                if (strcmp(op1_type->valuestring, "Immediate") == 0) {
                    fld->dontcare = false;
                    fld->value = malloc(round_up_to_8(pkt_field_defs[i].len)/8);
                    memcpy(fld->value, &val->valueint, round_up_to_8(pkt_field_defs[i].len)/8);
                } else {
                    logm(SL4C_ERROR, "Operand 1 type not supported\n");
                    return -1;
                }
            }
            i++;
        } // end match fields

        /*
         * Parse the action entry
         */
        (void)action;

        const cJSON *act_type = NULL;

        mat->entries[pri].act = malloc(sizeof(struct action_entry));

        struct action_entry *act = mat->entries[pri].act;

        act_type = cJSON_GetObjectItemCaseSensitive(action, "type");

        if (strcmp(act_type->valuestring, "XDPAction") == 0) {
            const cJSON *xdp_act = NULL;

            xdp_act = cJSON_GetObjectItemCaseSensitive(action, "xdp_action");

            if (strcmp(xdp_act->valuestring, "xdp_pass") == 0) {
                act->op = XDP_PASS;
            } else if (strcmp(xdp_act->valuestring, "xdp_drop") == 0) {
                act->op = XDP_DROP;
            } else if (strcmp(xdp_act->valuestring, "xdp_tx") == 0) {
                act->op = XDP_TX;
            } else if (strcmp(xdp_act->valuestring, "xdp_redirect") == 0) {
                act->op = XDP_REDIRECT;
            } else if (strcmp(xdp_act->valuestring, "xdp_aborted") == 0) {
                act->op = XDP_ABORTED;
            } else {
                logm(SL4C_ERROR, "XDP Action not recognized\n");
                return -1;
            }
        } else if (strcmp(act_type->valuestring, "AbandonAction") == 0) {
            act->op = ABANDON;
        } else if (strcmp(act_type->valuestring, "MapAccess") == 0) {
            const cJSON *map_id = NULL;
            const cJSON *pc = NULL, *context = NULL;

            map_id = cJSON_GetObjectItemCaseSensitive(action, "map_id");
            pc = cJSON_GetObjectItemCaseSensitive(action, "pc");
            context = cJSON_GetObjectItemCaseSensitive(action, "context");

            if (parse_context(act, context))
                return -1;

            act->op = MAP_ACCESS;
            act->pc = pc->valueint;
            act->map_id = map_id->valueint;
        } else {
            logm(SL4C_ERROR, "Action type not supported\n");
            return -1;
        }

        if (curr_entry == 0) {
            // Do this only the first time: packet field definition
            //      is the same for all the entries
            mat->field_defs = pkt_field_defs;
        }

        curr_entry++;
    } // end match entries

    return 0;
}

uint64_t
field_manipulation(enum alu_ops op, uint64_t imm,
                   uint64_t value,
                   uint8_t fld_len_in_bytes)
{
    uint64_t out_value;

    switch (op) {
        case ALU_OPS_BE:
        case ALU_OPS_LE:
            switch (fld_len_in_bytes) {
                case 8:
                    out_value = be64toh(value);
                    break;
                case 4:
                    out_value = be32toh(value);
                    break;
                case 2:
                    out_value = be16toh(value);
                    break;
                default:
                    logm(SL4C_ERROR, "Cannot perform le on this field length\n");
                    return 0xdeafbeefcafebabe;
            }
            break;
        case ALU_OPS_AND:
            out_value = (value) & imm;
            break;
        case ALU_OPS_OR:
            out_value = (value) | imm;
            break;
        case ALU_OPS_LSH:
            out_value = (value) << imm;
            break;
        case ALU_OPS_RSH:
            out_value = (value) >> imm;
            break;
        case ALU_OPS_ADD:
            out_value = (value) + imm;
            break;
        case ALU_OPS_NULL:
            out_value = value;
            break;
        default:
            logm(SL4C_ERROR, "Unrecognized operation on pkt field\n");
            break;
    }
    return out_value;
}

struct pkt_field *
parse_pkt_header(const u_char *pkt, struct match_table *mat)
{
    struct pkt_field_def *fld_def;
    struct pkt_field *ext_flds;

    ext_flds = malloc(sizeof(struct pkt_field) * mat->entries->nb_pkt_fields);

    for (int i=0; i < mat->entries->nb_pkt_fields; i++) {
        uint8_t fld_len_in_bytes;
        uint64_t value;

        fld_def = &mat->field_defs[i];

        fld_len_in_bytes = round_up_to_8(fld_def->len)/8;

        value = *(uint64_t *)(pkt + fld_def->offset);

        // Iterate over configured operations
        for (int j=0; j<fld_def->nb_ops; j++) {
            value = field_manipulation(fld_def->op[j], fld_def->imm[j],
                                       value, fld_len_in_bytes);
        }

        ext_flds[i].dontcare = false;
        ext_flds[i].value = malloc(fld_len_in_bytes);
        memcpy(ext_flds[i].value, &value, fld_len_in_bytes);
    } // end fields loop

    return ext_flds;
}

void
dump_fields(struct pkt_field *parsed_fields, uint8_t nb_fields)
{
    logm(SL4C_DEBUG, "Parsed fields:");
    for (int i=0; i<nb_fields; i++) {
        if (parsed_fields[i].value) {
            logm(SL4C_DEBUG, "\t#%d: %x", i, *(uint32_t *) parsed_fields[i].value);
        } else {
            logm(SL4C_DEBUG, "\t#%d: DONTCARE", i);
        }
    }
}

static inline bool
match_field(struct pkt_field *parsed_field, struct pkt_field *entry_field, int size)
{
    if (entry_field->dontcare) {
        return true;
    } else {
        if (memcmp(parsed_field->value, entry_field->value, size) == 0)
            return true;
        else
            return false;
    }
}

struct action_entry *
lookup_entry(struct match_table *mat, struct pkt_field *parsed_fields)
{
    for (int i=0; i<mat->nb_entries; i++) {
        dump_fields(mat->entries[i].fields, mat->entries->nb_pkt_fields);

        bool found = false;
        for (int j=0; j<mat->entries[i].nb_pkt_fields; j++) {
            struct pkt_field *entry_field = &mat->entries[i].fields[j];
            int field_size = round_up_to_8(mat->field_defs[j].len)/8;

            if (match_field(&parsed_fields[j], entry_field, field_size)) {
                if (j == mat->entries[i].nb_pkt_fields - 1)
                    found = true;
                continue;
            } else
                break;
        }
        if (found) {
            logm(SL4C_INFO, "Matched entry number: %d", i);
            mat->entries[i].cnt++;
            return mat->entries[i].act;
        }
    }

    return NULL;
}

/*
u_char *
generate_key(struct action_entry *act, const u_char *pkt, size_t *key_len)
{
    u_char *key = NULL;

    *key_len = act->key_len + 1;
    key = malloc(act->key_len + 1);

    for (int i = 0; i < act->nb_key_fields; i++) {
        size_t start, end, offset, fld_len_in_bytes, nb_ops;
        enum alu_ops op;
        uint64_t imm, value;

        start = act->key_fields[i].kstart;
        end = act->key_fields[i].kend;

        if (act->key_fields[i].has_imm) {
            memcpy(&key[start], &act->key_fields[i].imm, end - start);
            continue;
        }

        fld_len_in_bytes = round_up_to_8(act->key_fields[i].pkt_fld.len)/8;
        offset = act->key_fields[i].pkt_fld.offset;
        nb_ops = act->key_fields[i].pkt_fld.nb_ops;

        value = *(uint64_t *) (pkt + offset);

        for (int j=0; j<nb_ops; j++) {
            op = act->key_fields[i].pkt_fld.op[j];
            imm = act->key_fields[i].pkt_fld.imm[j];

            value = field_manipulation(op, imm, value, fld_len_in_bytes);
        }

        memcpy(&key[start], &value, end - start);
    }

    memset(&key[act->key_len], act->map_id, 1);

    return key;
}*/