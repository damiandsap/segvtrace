#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include "monitor-common.h"

static int read_physical_core(int logical_cpu)
{
    char path[256];
    FILE *fp;
    int core_id;

    snprintf(path, sizeof(path),
            "/sys/devices/system/cpu/cpu%d/topology/core_id",
            logical_cpu);

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (fscanf(fp, "%d", &core_id) != 1)
        core_id = -1;

    fclose(fp);
    return core_id;
}

static int read_package(int logical_cpu)
{
    char path[256];
    FILE *fp;
    int package_id;

    snprintf(path, sizeof(path),
            "/sys/devices/system/cpu/cpu%d/topology/physical_package_id",
            logical_cpu);

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (fscanf(fp, "%d", &package_id) != 1)
        package_id = -1;

    fclose(fp);
    return package_id;
}

int init_cpu_topology(struct cpu_topology *topology)
{
    topology->num_cpus = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (topology->num_cpus <= 0)
    {
        fprintf(stderr, "Failed to create CPU topology due to failure in obtaining the CPU count");
        return -1;
    }

    topology->cpu_core_ids = calloc(topology->num_cpus, sizeof(*topology->cpu_core_ids));
    topology->cpu_package_ids = calloc(topology->num_cpus, sizeof(*topology->cpu_package_ids));

    if (!topology->cpu_core_ids || !topology->cpu_package_ids) {
        free(topology->cpu_core_ids);
        free(topology->cpu_package_ids);
        topology->cpu_core_ids = NULL;
        topology->cpu_package_ids = NULL;
        fprintf(stderr, "Failed to create CPU topology due to insufficient space");
        return -1;
    }

    for (int cpu = 0; cpu < topology->num_cpus; cpu++) {
        topology->cpu_core_ids[cpu] = read_physical_core(cpu);
        topology->cpu_package_ids[cpu] = read_package(cpu);

        if (topology->cpu_core_ids[cpu] < 0 || topology->cpu_package_ids[cpu] < 0) {
            fprintf(stderr,
                    "Failed to read CPU topology for CPU %d: "
                    "core=%d package=%d errno=%d\n",
                    cpu,
                    topology->cpu_core_ids[cpu],
                    topology->cpu_package_ids[cpu],
                    errno);

            free(topology->cpu_core_ids);
            free(topology->cpu_package_ids);
            topology->cpu_core_ids = NULL;
            topology->cpu_package_ids = NULL;
            return -1;
        }
    }

    return 0;
}

void free_cpu_topology(struct cpu_topology *topology)
{
    free(topology->cpu_core_ids);
    free(topology->cpu_package_ids);
    topology->cpu_core_ids = NULL;
    topology->cpu_package_ids = NULL;
}

int get_physical_core(struct cpu_topology *topology, int logical_cpu)
{
    if (logical_cpu >= 0) {
        if (logical_cpu < topology->num_cpus) {
            return topology->cpu_core_ids[logical_cpu];
        } else {
            fprintf(stderr, "WARNING: CPU %d does not exist in topology cache. Attempting to read core id from system: ", logical_cpu);
            return read_physical_core(logical_cpu);
        }
    } else {
        fprintf(stderr, "WARNING: %d is an invalid CPU id", logical_cpu);
        return -1;
    }
}

int get_package(struct cpu_topology *topology, int logical_cpu)
{
    if (logical_cpu >= 0) {
        if (logical_cpu < topology->num_cpus) {
            return topology->cpu_package_ids[logical_cpu];
        } else {
            fprintf(stderr, "WARNING: CPU %d does not exist in topology cache. Attempting to read package id from system: ", logical_cpu);
            return read_package(logical_cpu);
        }
    } else {
        fprintf(stderr, "WARNING: %d is an invalid CPU id", logical_cpu);
        return -1;
    }
}

const char* get_cgroup_version(void)
{
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp)
        return "none";

    char *line = NULL;
    size_t len = 0;
    bool v1 = false;
    bool v2 = false;

    while (getline(&line, &len, fp) != -1) {
        char *sep = strstr(line, " - ");
        if (!sep)
            continue;

        sep += 3;

        if (strncmp(sep, "cgroup2 ", 8) == 0)
            v2 = true;
        else if (strncmp(sep, "cgroup ", 7) == 0)
            v1 = true;

        if (v1 && v2)
            break;
    }

    free(line);
    fclose(fp);

    if (v1 && v2)
        return "hybrid";

    if (v1)
        return "v1";

    if (v2)
        return "v2";

    return "none";
}

void print_version(char const* prefix, FILE* out) {
    fprintf(out, "%scommit %s committed on %s, kernel %d\n", prefix, GIT_REV, GIT_DATE, KERNEL_VERSION);
}

void print_opcodes(const char *name, struct opcode_list *list, char suffix)
{
    printf("\"%s\":{\"err\":%lld,\"opcodes\":", name, list->err);
    if (list->err != 1) {
        printf("\"");
        for (int i = 0; i < OPCODES_SIZE; i++)
            printf("%02x", list->opcodes[i]);
        printf("\"");
    }
    else
    {
        printf("null");
    }

    printf("}%c", suffix);
}

void print_pf_info(struct pf_info *pf, struct cpu_topology *topology)
{
    int core = get_physical_core(topology, pf->cpu);
    int package = get_package(topology, pf->cpu);

    printf("{\"ip\":\"0x%016llx\",\"cpu\":%u,\"core\":%d,\"package\":%d,\"cr2\":\"0x%016llx\",\"err\":\"0x%016llx\",\"tai\":%llu,",
            pf->ip, pf->cpu, core, package, pf->cr2, pf->err, pf->tai);
    print_opcodes("ip_snapshot", &pf->opcodes_ip, '}');
}
