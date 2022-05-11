import re

import lief
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import sys
import json

# from hxdp_compiler.maps import BPFMap, BPFProgramMaps
# from hxdp_compiler.packer_unpacker import BPF_INSN_SZ_B

BPF_INSN_SZ_B = 8

INSTR_REGEX = '([A-Fa-f0-9]{2}( )){7}([A-Fa-f0-9]{2})(( )([A-Fa-f0-9]{2}( )){7}([A-Fa-f0-9]{2}))?'
COMMENTS_REGEX = '(;).*?'

MAPS_DEF_STRUCT_FIELD_SZ_B = 4

class ELFParsingError(Exception):
    pass


def read_file_elf(filename, secname):
    # parse file as elf, 'allocate' maps file descriptors and returns the list of instructions as integers,
    # and the list of str mnemonics

    maps = []  # maps defined by the program
    tb_relocated = []  # instructions accessing maps

    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name(".symtab")
        symtab_syms = list(symtab.iter_symbols())

        strtab = elffile.get_section_by_name(".strtab")

        reladyn_name = ".rel" + secname
        reladyn = elffile.get_section_by_name(reladyn_name)

        # 1. parse maps relocation section, obtaining instructions to be modified & used maps
        insn_orig_pos_to_map_offset = {}  # insn_orig_pos: offset inside maps section
        map_to_offsets = {}
        map_names = {}
        if isinstance(reladyn, RelocationSection):
            for reloc in reladyn.iter_relocations():
                idx = int(reloc['r_offset'] / BPF_INSN_SZ_B)  # instruction original position
                insn_orig_pos_to_map_offset[idx] = symtab_syms[reloc['r_info_sym']]['st_value']
                map_id = symtab_syms[reloc['r_info_sym']]['st_value']
                if map_id not in map_to_offsets:
                    map_to_offsets[map_id] = []
                map_to_offsets[map_id].append(idx)

                name_off = symtab_syms[reloc['r_info_sym']]['st_name']
                map_names[map_id] = strtab.get_string(name_off)

            # 1-b. parse maps section
            maps_sec = elffile.get_section_by_name('maps')
            maps_sec = elffile.get_section_by_name('.maps') if maps_sec is None else maps_sec
            if maps_sec is None:
                raise ELFParsingError("invalid ELF file: found relocation sec %s but no maps section" % reladyn_name)

            for mid, map_off in enumerate(set(insn_orig_pos_to_map_offset.values())):
                maps_data = maps_sec.data()
                type = int.from_bytes(maps_data[map_off:map_off + MAPS_DEF_STRUCT_FIELD_SZ_B], byteorder='little')
                key_sz = int.from_bytes(
                    maps_data[map_off + MAPS_DEF_STRUCT_FIELD_SZ_B:map_off + 2 * MAPS_DEF_STRUCT_FIELD_SZ_B],
                    byteorder='little')
                value_sz = int.from_bytes(
                    maps_data[map_off + 2 * MAPS_DEF_STRUCT_FIELD_SZ_B:map_off + 3 * MAPS_DEF_STRUCT_FIELD_SZ_B],
                    byteorder='little')
                max_entries = int.from_bytes(
                    maps_data[map_off + 3 * MAPS_DEF_STRUCT_FIELD_SZ_B:map_off + 4 * MAPS_DEF_STRUCT_FIELD_SZ_B],
                    byteorder='little')

                maps.append({"id": mid,
                             "offsets": map_to_offsets[map_off],
                             "type": type,
                             "key_size": key_sz,
                             "value_size": value_sz,
                             "max_entries": max_entries,
                             "name": map_names[map_off]})

        # 3. parse instruction section
        elf = lief.parse(filename)
        code = elf.get_section(secname)

        prog_bin = []
        for i in range(0, len(code.content), BPF_INSN_SZ_B):
            ins = int.from_bytes(code.content[i:i + BPF_INSN_SZ_B], byteorder='big')

            idx = int(i / BPF_INSN_SZ_B)
            if idx in insn_orig_pos_to_map_offset:
                tb_relocated.append(idx)
            #    maps.add_map_reference(insn_orig_pos_to_map_offset[idx], idx)

            prog_bin.append(ins)

        return prog_bin, tb_relocated, maps


def read_file_dump(filename: str):
    # parse file and returns the list of instructions as integers, and the list of str mnemonics

    program_bin = []
    program_str = []
    for line in open(filename, 'r'):
        if not re.search(COMMENTS_REGEX, line):  # ignore comment line
            instr_match = re.search(INSTR_REGEX, line)

            if instr_match:
                instr_s = line[instr_match.regs[0][1]:].lstrip().replace("\n", "")
                label = re.search(r"(<)\w+(>)", instr_s)
                if label:
                    instr_s = instr_s[:label.regs[0][0]]

                program_str.append(instr_s)

                program_bin.append(int(instr_match.group(0).replace(' ', '')[:16], 16))

                if len(instr_match.group(0).replace(' ', '')) > 16:
                    program_bin.append(0)
                    program_str.append("NOP")

    return program_bin, program_str


def print_line(line):
    bins = "{0:64b}".format(line).replace(" ", "0")
    print("|" + bins[:8] + "|" + bins[8:12] + "|" + bins[12:16] + "|" + bins[16:32] + "|" + bins[32:64] + "|")


filename = sys.argv[1]

secname = sys.argv[3]

prog_bin, tb_relocated, maps = read_file_elf(filename, secname)

print(tb_relocated)
print(maps)

file = open(sys.argv[2]+".bin", "wb")

for ins in prog_bin:
    file.write(int.to_bytes(ins, BPF_INSN_SZ_B, byteorder="big"))

file.close()

json_file = open(sys.argv[2]+"_maps.json", "w")
json_file.write(json.dumps(maps, indent=4))
json_file.close()

print("Saved program in "+sys.argv[2]+".bin and map definitions in "+sys.argv[2]+"_maps.json")
