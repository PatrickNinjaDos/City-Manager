#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
 
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
 
    return 0;
}