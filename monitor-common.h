#pragma once

#include <stdio.h>
#include <stdbool.h>

#include "monitor-types.h"

#define for_each(i, cond) for (int (i) = 0; (i) < (cond); (i)++)
#define for_each_cpu(cpu) for_each(cpu, get_nprocs_conf())

struct cpu_topology {
    int *cpu_core_ids;
    int *cpu_package_ids;
    int num_cpus;
};

int init_cpu_topology(struct cpu_topology *topology);
void free_cpu_topology(struct cpu_topology *topology);
int get_physical_core(struct cpu_topology *topology, int logical_cpu);
int get_package(struct cpu_topology *topology, int logical_cpu);

const char *get_cgroup_version(void);
void print_version(const char *prefix, FILE *out);
void print_opcodes(const char *name, struct opcode_list *list, char suffix);
void print_pf_info(struct pf_info *pf, struct cpu_topology *topology);
