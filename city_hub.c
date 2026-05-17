#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PID_FILE ".monitor_pid"
#define MAX_DISTRICTS 16
#define BUF_SIZE 256

//sa stim daca e sau nu activ monitorul
static pid_t hub_mon_pid = -1;

int main(void) {
    printf("=== city_hub ===\n");
    printf("Tasteaza 'help' pentru lista de comenzi.\n\n");
 
    return 0;
}