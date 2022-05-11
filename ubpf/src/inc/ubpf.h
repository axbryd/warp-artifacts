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

#ifndef UBPF_H
#define UBPF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "../match_unit.h"

struct ubpf_vm;
struct ubpf_map;
struct ubpf_func_proto;

typedef uint64_t (*ubpf_jit_fn)(void *mem, size_t mem_len);

struct ubpf_vm *ubpf_create(void);
void ubpf_destroy(struct ubpf_vm *vm);

struct xdp_md {
  uintptr_t data;
  uintptr_t data_end;
};

struct map_context {
  uint16_t pc;
  uint64_t *reg;
  uint64_t *stack;
  uint64_t *old_reg;
  uint64_t *old_stack;
};

/*
 * Enable / disable bounds_check
 *
 * Bounds check is enabled by default, but it may be too restrictive
 * Pass true to enable, false to disable
 * Returns previous state
 */
bool toggle_bounds_check(struct ubpf_vm *vm, bool enable);

/*
 * Register an external function
 *
 * The immediate field of a CALL instruction is an index into an array of
 * functions registered by the user. This API associates a function with
 * an index.
 *
 * 'name' should be a string with a lifetime longer than the VM.
 *
 * Returns 0 on success, -1 on error.
 */
int ubpf_register_function(struct ubpf_vm *vm, unsigned int idx, const char *name, struct ubpf_func_proto proto);

/*
 * Register an external variable.
 *
 * 'name' should be a string with a lifetime longer than the VM.
 *
 * Returns 0 on success, -1 on error.
 */
int ubpf_register_map(struct ubpf_vm *vm, const char *name, struct ubpf_map *map);

/*
 * Load code into a VM
 *
 * This must be done before calling ubpf_exec or ubpf_compile and after
 * registering all functions.
 *
 * 'code' should point to eBPF bytecodes and 'code_len' should be the size in
 * bytes of that buffer.
 *
 * Returns 0 on success, -1 on error. In case of error a pointer to the error
 * message will be stored in 'errmsg' and should be freed by the caller.
 */
int ubpf_load(struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg);

/*
 * Load code from an ELF file
 *
 * This must be done before calling ubpf_exec or ubpf_compile and after
 * registering all functions.
 *
 * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
 * be the size in bytes of that buffer.
 *
 * The ELF file must be 64-bit little-endian with a single text section
 * containing the eBPF bytecodes. This is compatible with the output of
 * Clang.
 *
 * Returns 0 on success, -1 on error. In case of error a pointer to the error
 * message will be stored in 'errmsg' and should be freed by the caller.
 */
int ubpf_load_elf(struct ubpf_vm *vm, const void *elf, size_t elf_len, char **errmsg);

uint64_t ubpf_exec(const struct ubpf_vm *vm, struct xdp_md *xdp,
                   struct reg_def *regs_def, struct stack_def *stack,
                   uint16_t pc_start, uint8_t map_id);

ubpf_jit_fn ubpf_compile(struct ubpf_vm *vm, char **errmsg);

#endif
