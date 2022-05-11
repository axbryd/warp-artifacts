# Copyright 2015 Big Switch Networks, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CFLAGS := -Wall -Werror -Iinc -O0 -g -Wunused-parameter
LDLIBS := -lm -lpcap

INSTALL ?= install
DESTDIR =
PREFIX ?= /usr/local

ifeq ($(COVERAGE),1)
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs
endif

ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

all: clean libubpf.a hXDP_sim

sclog4c.o: sclog4c.c

lookup3.o: lookup3.c lookup3.h

ubpf_array.o: ubpf_array.c

ubpf_hashmap.o: ubpf_hashmap.c ubpf_hashmap.h

ubpf_lpm.o: ubpf_lpm.c ubpf_lpm.h

helper_functions.o: helper_functions.c helper_functions.h

libubpf.a: ubpf_vm.o sclog4c.o lookup3.o ubpf_array.o helper_functions.o ubpf_hashmap.o ubpf_lpm.o
	ar rc $@ $^

cJSON.o: cJSON.c

match_unit.o: match_unit.c

hXDP_sim: hXDP_sim.o cJSON.o match_unit.o libubpf.a

install:
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -m 644 libubpf.a $(DESTDIR)$(PREFIX)/lib
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/include
	$(INSTALL) -m 644 inc/ubpf.h $(DESTDIR)$(PREFIX)/include

clean:
	rm -f test libubpf.a *.o hXDP_sim
