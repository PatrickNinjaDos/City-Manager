#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_INSPECTORS 64

typedef struct {
    char name[32];
    uint32_t total_severity;
} InspectorScore;
 
typedef struct {
    uint32_t report_id;
    char inspector_name[32];
    float latitude;
    float longitude;
    char category[32];
    uint32_t severity;
    time_t timestamp;
    char description[128];
} __attribute__((packed)) Report;

int main(int argc, char *argv[]) 
{
    if (argc < 2) {
        fprintf(stderr, "usage: scorer <district_id>\n");
        return 1;
    }

    char filepath[128];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", argv[1]);
 
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "eroare la deschidere%s\n", filepath);
        return 1;
    }
 
    return 0;
}