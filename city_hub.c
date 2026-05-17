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

pid_t read_monitor_pid() 
{
    int fd = open(PID_FILE, O_RDONLY);
    if (fd < 0) return -1;
 
    char buf[32];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return -1;
    buf[n] = '\0';
    // returneaza -1 daca nu exista sau daca pid-ul nu e valid
    return (pid_t)atoi(buf);
}

void run_hub_mon() {
    // pipe intre monitor si hub_mo
    n
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("hub_mon: pipe");
        exit(1);
    }
 
    pid_t mon_pid = fork();
    if (mon_pid < 0) {
        perror("hub_mon: fork monitor");
        exit(1);
    }
 
    if (mon_pid == 0) {
        // proces copil => monitor_reports
        // redirectam stdout -> capatul de scriere al pipe-ului
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
 
        execlp("./monitor_reports", "monitor_reports", NULL);
        perror("hub_mon: exec monitor_reports");
        exit(1);
    }
 
    // hub_mon citeste din capatul de citire
    close(pipefd[1]);
 
    char line[BUF_SIZE];
    int i = 0;
    char c;
    // citim caracter cu caracter => afisam linie cu linie
    while (read(pipefd[0], &c, 1) == 1) {
        if (c == '\n' || i == BUF_SIZE - 2) {
            line[i] = '\0';
            i = 0;
            if (strlen(line) > 0) {
                printf("[monitor] %s\n", line);
                fflush(stdout);
            }
            if (strstr(line, "SIGINT") || strstr(line, "oprire") ||
                strstr(line, "eroare") || strstr(line, "deja pornit")) {
                printf("[hub] monitorul s-a oprit.\n");
                fflush(stdout);
                break;
            }
        } else {
            line[i++] = c;
        }
    }
    close(pipefd[0]);
 
    // asteptam monitorul sa se termine
    waitpid(mon_pid, NULL, 0);
    exit(0);
}

int main(void) {
    printf("=== city_hub ===\n");
    printf("Tasteaza 'help' pentru lista de comenzi.\n\n");
 
    char input[512];
    while (1) {
        printf("hub> ");
        fflush(stdout);
 
        if (fgets(input, sizeof(input), stdin) == NULL) {
            // EOF (Ctrl+D)
            printf("\n[hub] iesire.\n");
            break;
        }
 
        // ignoram linii goale
        if (input[0] == '\n') continue;
 
        parse_and_run(input);
 
        // curatam zombie-uri fara sa blocam
        waitpid(-1, NULL, WNOHANG);
    }
    return 0;
}