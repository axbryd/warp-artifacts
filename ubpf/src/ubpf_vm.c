/*
 * Copyright 2015 Big Switch Networks, Inc
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include "ubpf_int.h"
#include "inc/sclog4c.h"

#define MAX_EXT_FUNCS 128
#define MAX_EXT_MAPS 64

static bool validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg);
static bool bounds_check(const struct ubpf_vm *vm, void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len, void *stack);

bool toggle_bounds_check(struct ubpf_vm *vm, bool enable)
{
  bool old = vm->bounds_check_enabled;
  vm->bounds_check_enabled = enable;
  return old;
}

struct ubpf_vm *
ubpf_create(void)
{
    struct ubpf_vm *vm = calloc(1, sizeof(*vm));
    if (vm == NULL) {
        return NULL;
    }

    vm->ext_funcs = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
    if (vm->ext_funcs == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->ext_func_names = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
    if (vm->ext_func_names == NULL) {
        ubpf_destroy(vm);
        return NULL;
    }

    vm->ext_maps = calloc(MAX_EXT_MAPS, sizeof(*vm->ext_maps));
    vm->ext_map_names = calloc(MAX_EXT_MAPS, sizeof(*vm->ext_map_names));
    vm->nb_maps = 0;

    vm->bounds_check_enabled = false;
    return vm;
}

void
ubpf_destroy(struct ubpf_vm *vm)
{
    if (vm->jitted) {
        munmap(vm->jitted, vm->jitted_size);
    }
    free(vm->insts);
    free(vm->ext_funcs);
    free(vm->ext_func_names);
    free(vm);
}

/*
int
ubpf_register(struct ubpf_vm *vm, unsigned int idx, const char *name, void *fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = (ext_func)fn;
    vm->ext_func_names[idx] = name;
    return 0;
}
*/

int
ubpf_register_function(struct ubpf_vm *vm, unsigned int idx, const char *name,
                       struct ubpf_func_proto proto)
{
  if (idx >= MAX_EXT_FUNCS) {
    return -1;
  }

  vm->ext_funcs[idx] = proto;
  vm->ext_func_names[idx] = name;
  return 0;
}

int
ubpf_register_map(struct ubpf_vm *vm, const char *name, struct ubpf_map *map)
{
  unsigned int idx = vm->nb_maps;
  if (idx >= MAX_EXT_MAPS) {
    return -1;
  }
  vm->ext_maps[idx] = map;
  vm->ext_map_names[idx] = name;
  vm->nb_maps++;
  return 0;
}

unsigned int
ubpf_lookup_registered_function(struct ubpf_vm *vm, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char *other = vm->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

struct ubpf_map *
ubpf_lookup_registered_map(struct ubpf_vm *vm, const char *name)
{
  int i;
  for (i = 0; i < MAX_EXT_MAPS; i++) {
    const char *other = vm->ext_map_names[i];
    if (other && !strcmp(other, name)) {
      return vm->ext_maps[i];
    }
  }
  return NULL;
}

int
ubpf_load(struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg)
{
    *errmsg = NULL;

    if (vm->insts) {
        *errmsg = ubpf_error("code has already been loaded into this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ubpf_error("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len/8, errmsg)) {
        return -1;
    }

    vm->insts = malloc(code_len);
    if (vm->insts == NULL) {
        *errmsg = ubpf_error("out of memory");
        return -1;
    }

    memcpy(vm->insts, code, code_len);
    vm->num_insts = code_len/sizeof(vm->insts[0]);

    return 0;
}

static uint32_t
u32(uint64_t x)
{
    return x;
}

static inline void
dump_stack(uint64_t *stack)
{
    for (int i=0; i < (STACK_SIZE+7)/8; i++) {
        fprintf(stderr, "%016lx ", stack[i]);
        if (i%4 == 0) {
            fprintf(stderr, "\n%04x:\t", i*8);
        }
    }

    fprintf(stderr, "\n");
}

static inline void
restore_context(struct reg_def *regs_def, struct stack_def *stack_def,
                uint64_t *reg, uint64_t *stack, struct xdp_md *xdp,
                const struct ubpf_vm *vm, uint8_t map_id, uint16_t pc) {
    int i, j;
    uintptr_t stack_ptr = (uintptr_t) stack + ((STACK_SIZE+7)/8 * sizeof(uint64_t));
    uintptr_t pkt_ptr = (uintptr_t) xdp->data;
    struct key_field *fld;

    /*
     * Restore registers
     */
    for (i = 0; i <= 10; i++) {
        // register 1, i.e. the relocated map pointer
        if (i == 1 && vm->insts[pc].opcode == EBPF_OP_CALL) {
            reg[i] = (uintptr_t) vm->ext_maps[map_id];
            continue;
        }

        switch (regs_def[i].type) {
            case REG_DEF_IMM:
                reg[i] = regs_def[i].val;
                break;
            case REG_DEF_STACK_PTR:
                reg[i] = stack_ptr + regs_def[i].offset;
                break;
            case REG_DEF_PKT_PTR:
                reg[i] = pkt_ptr + regs_def[i].offset;
                break;
            case REG_DEF_PKT_END:
                reg[i] = xdp->data_end;
                break;
            case REG_DEF_CTX_PTR:
                reg[i] = (uintptr_t) xdp;
                break;
            case REG_DEF_PKT_FLD:
            {
                size_t fld_len_in_bytes, offset, nb_ops, op, imm;
                uint64_t value;

                fld_len_in_bytes = round_up_to_8(regs_def[i].pkt_fld.len) / 8;
                offset = regs_def[i].pkt_fld.offset;
                nb_ops = regs_def[i].pkt_fld.nb_ops;

                value = *(uint64_t *) (pkt_ptr + offset);

                for (j = 0; j < nb_ops; j++) {
                    op = regs_def[i].pkt_fld.op[j];
                    imm = regs_def[i].pkt_fld.imm[j];

                    value = field_manipulation(op, imm, value, fld_len_in_bytes);
                }

                memcpy(&reg[i], &value, fld_len_in_bytes);

                break;
            }
            case REG_DEF_NULL:
            default:
                break;
        }
    }

    /*
     * Restore stack
     */

    for (i = 0; i < stack_def->nb_fields; i++) {
        size_t start, end, len;
        size_t fld_len_in_bytes, offset, nb_ops, op, imm;
        uint64_t value;

        fld = &stack_def->key_fields[i];

        start = fld->kstart;
        end = fld->kend;

        len = end - start;

        if (fld->has_imm) {
            if (fld->type == REG_DEF_PKT_PTR) {
                offset = fld->imm;
                *(uint64_t *)(stack_ptr + start) = (uint64_t) (pkt_ptr + offset);
                continue;
            } else if (fld->type == REG_DEF_STACK_PTR) {
                offset = fld->imm;
                *(uint64_t *)(stack_ptr + start) = (uint64_t) (stack_ptr + offset);
                continue;
            }
            if (len > sizeof(uint64_t)) {
                if (fld->imm != 0) {
                    logm(SL4C_ERROR, "Immediate is greater than zero but len is greater than 8 bytes");
                    return;
                }
                memset((void *) (stack_ptr + start), 0, len);
            }
            else
                memcpy((void *)(stack_ptr + start), &fld->imm, len);
            continue;
        }

        fld_len_in_bytes = round_up_to_8(fld->pkt_fld.len) / 8;
        offset = fld->pkt_fld.offset;
        nb_ops = fld->pkt_fld.nb_ops;

        value = *(uint64_t *) (pkt_ptr + offset);

        for (j = 0; j < nb_ops; j++) {
            op = fld->pkt_fld.op[j];
            imm = fld->pkt_fld.imm[j];

            value = field_manipulation(op, imm, value, fld_len_in_bytes);
        }

        memcpy((void *)(stack_ptr + start), &value, len);
    }
}

static inline void
dump_registers(uint64_t *reg) {
    fprintf(stderr, "R0: %016lx \nR1: %016lx \nR2: %016lx\n", reg[0], reg[1], reg[2]);
    fprintf(stderr, "R3: %016lx \nR4: %016lx \nR5: %016lx\n", reg[3], reg[4], reg[5]);
    fprintf(stderr, "R6: %016lx \nR7: %016lx \nR8: %016lx\n", reg[6], reg[7], reg[8]);
    fprintf(stderr, "R9: %016lx \nR10: %016lx\n", reg[9], reg[10]);
}

uint64_t
ubpf_exec(const struct ubpf_vm *vm, struct xdp_md *xdp,
          struct reg_def *regs_def, struct stack_def *stack_def,
          uint16_t pc_start, uint8_t map_id)
{
    uint16_t pc = 0;
    const struct ebpf_inst *insts = vm->insts;
    uint64_t reg[16] = {0};
    uint16_t stack_size = ((STACK_SIZE+7)/8) * sizeof(uint64_t);
    uint64_t stack[((STACK_SIZE+7)/8) * sizeof(uint64_t)] = {0};
    unsigned int insts_count = 0;

    if (!insts) {
        /* Code must be loaded before we can execute */
        return UINT64_MAX;
    }

    if (regs_def && stack_def) {
        pc = pc_start;

        restore_context(regs_def, stack_def, reg, stack, xdp, vm, map_id, pc);

        logm(SL4C_DEBUG, "--------------- Restoring context");

        /*fprintf(stderr, "pkt_head_ptr: %p\n", xdp);
        fprintf(stderr, "stack_ptr: %p\n", stack + stack_size);
        dump_registers(reg);
        dump_stack(stack);*/
    } else {
        reg[1] = (uintptr_t) xdp;
        reg[10] = (uintptr_t)stack + stack_size;
    }

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = insts[pc++];

        logm(SL4C_DEBUG, "opcode=0x%02X, PC: %d", inst.opcode, pc-1);
        /*printf("pc: %d\n", pc-1);
        if (inst.opcode == 0x18)
            printf("pc: %d\n", pc);*/

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst] += inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst] += reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst] -= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst] -= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst] *= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst] *= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (reg[inst.src] == 0) {
                logm(SL4C_ERROR, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst] |= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst] |= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst] &= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst] &= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst] <<= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] <<= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (reg[inst.src] == 0) {
                logm(SL4C_ERROR, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst] ^= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst] ^= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst] = inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst] = reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst] = htole16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htole32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htole64(reg[inst.dst]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst] = htobe16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htobe32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htobe64(reg[inst.dst]);
            }
            break;


        case EBPF_OP_ADD64_IMM:
            reg[inst.dst] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst] += reg[inst.src];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst] -= reg[inst.src];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst] *= reg[inst.src];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst] /= inst.imm;
            break;
        case EBPF_OP_DIV64_REG:
            if (reg[inst.src] == 0) {
                logm(SL4C_ERROR, "uBPF error: division by zero at PC %u", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] /= reg[inst.src];
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst] |= reg[inst.src];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst] &= reg[inst.src];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= reg[inst.src];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= reg[inst.src];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst] = -reg[inst.dst];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst] %= inst.imm;
            break;
        case EBPF_OP_MOD64_REG:
            if (reg[inst.src] == 0) {
                logm(SL4C_ERROR, "uBPF error: division by zero at PC %u", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] %= reg[inst.src];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst] ^= reg[inst.src];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst] = reg[inst.src];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
            break;

        /*
         * HACK runtime bounds check
         *
         * Needed since we don't have a verifier yet.
         */
#define BOUNDS_CHECK_LOAD(size) \
    do { \
        if (!bounds_check(vm, (void *)reg[inst.src] + inst.offset, size, "load", cur_pc, (void*) xdp->data, xdp->data_end - xdp->data, stack)) { \
            return UINT64_MAX; \
        } \
    } while (0)
#define BOUNDS_CHECK_STORE(size) \
    do { \
        if (!bounds_check(vm, (void *)reg[inst.dst] + inst.offset, size, "store", cur_pc, (void*)xdp->data, xdp->data_end - xdp->data, stack)) { \
            return UINT64_MAX; \
        } \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            if ((uintptr_t)(reg[inst.src] + inst.offset) == (uintptr_t)xdp) {
                reg[inst.dst] = (uintptr_t)(xdp->data);
            } else if ((uintptr_t)(reg[inst.src] + inst.offset) == (uintptr_t)xdp + 4) {
                reg[inst.dst] = (xdp->data_end);
            } else {
                reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            }
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = (uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst] < (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst] < reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst] <= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst] <= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst] < inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst] <= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            logm(SL4C_DEBUG, "------- R0: %016lx | R1: %016lx | R2: %016lx", reg[0], reg[1], reg[2]);
            logm(SL4C_DEBUG, "------- R3: %016lx | R4: %016lx | R5: %016lx", reg[3], reg[4], reg[5]);
            logm(SL4C_DEBUG, "------- R6: %016lx | R7: %016lx | R8: %016lx", reg[6], reg[7], reg[8]);
            logm(SL4C_DEBUG, "------- R9: %016lx | R10: %016lx\n", reg[9], reg[10]);

            uint64_t reg0_tmp = reg[0];

            if (sclog4c_level <= SL4C_DEBUG)
                dump_stack(stack);

            insts_count++;
            logm(SL4C_INFO, "Instructions count: %u", insts_count);

            return reg0_tmp;
        case EBPF_OP_CALL:
            reg[0] = vm->ext_funcs[inst.imm].func(reg[1], reg[2], reg[3], reg[4], reg[5]);

            logm(SL4C_DEBUG, "Calling %d, reg[0]=%lx, map_id=%lx", inst.imm, reg[0], (long)reg[1]);

            if (inst.imm == MAP_LOOKUP) {
                struct ubpf_map *map = NULL;
                size_t key_size;
                int ki, m;

                for (m=0; m<vm->nb_maps; m++) {
                    if ((uintptr_t)vm->ext_maps[m] == reg[1]) {
                        map = vm->ext_maps[m];
                        break;
                    }
                }
                if (map) {
                    key_size = map->key_size;

                    logm(SL4C_DEBUG, "Dumping requested map (%d) key", m);
                    if (reg[2]) {
                        for (ki=0; ki<key_size; ki++)
                            logm(SL4C_DEBUG, "key[%d]: 0x%02x", ki, *(uint8_t*)(reg[2] + ki));
                    }
                }
            }

            if (reg[0])
                logm(SL4C_DEBUG, "There's a match");
            break;
        }

        logm(SL4C_DEBUG, "------- R0: %016lx | R1: %016lx | R2: %016lx", reg[0], reg[1], reg[2]);
        logm(SL4C_DEBUG, "------- R3: %016lx | R4: %016lx | R5: %016lx", reg[3], reg[4], reg[5]);
        logm(SL4C_DEBUG, "------- R6: %016lx | R7: %016lx | R8: %016lx", reg[6], reg[7], reg[8]);
        logm(SL4C_DEBUG, "------- R9: %016lx | R10: %016lx\n", reg[9], reg[10]);

        insts_count++;
    }
}

static bool
validate(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
{
    if (num_insts >= MAX_INSTS) {
        *errmsg = ubpf_error("too many instructions (max %u)", MAX_INSTS);
        return false;
    }

    int i;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        bool store = false;

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
                *errmsg = ubpf_error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
            if (inst.offset == -1) {
                *errmsg = ubpf_error("infinite loop at PC %d", i);
                return false;
            }
            int new_pc = i + 1 + inst.offset;
            if (new_pc < 0 || new_pc >= num_insts) {
                *errmsg = ubpf_error("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].opcode == 0) {
                *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                *errmsg = ubpf_error("invalid call immediate at PC %d, imm=%u", i, inst.imm);
                return false;
            }
            if (!vm->ext_funcs[inst.imm].func) {
                *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                *errmsg = ubpf_error("division by zero at PC %d", i);
                return false;
            }
            break;

        default:
            *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }

        if (inst.src > 10) {
            *errmsg = ubpf_error("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst > 9 && !(store && inst.dst == 10)) {
            *errmsg = ubpf_error("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

static bool
bounds_check(const struct ubpf_vm *vm, void *addr, int size, const char *type, uint16_t cur_pc, void *mem, size_t mem_len, void *stack)
{
    if (!vm->bounds_check_enabled)
        return true;
    if (mem && (addr >= mem && (addr + size) <= (mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && (addr + size) <= (stack + STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        logm(SL4C_ERROR, "uBPF error: out of bounds memory %s at PC %u, addr %p, size %d\n", type, cur_pc, addr, size);
        logm(SL4C_ERROR, "mem %p/%zd stack %p/%d\n", mem, mem_len, stack, STACK_SIZE);
        return false;
    }
}

char *
ubpf_error(const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}
