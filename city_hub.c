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

void cmd_start_monitor() {
    // verificam daca hub_mon e deja activ
    if (hub_mon_pid > 0) {
        // verificam daca procesul exista inca
        if (kill(hub_mon_pid, 0) == 0) {
            printf("[hub] monitorul este deja pornit (hub_mon PID=%d).\n", hub_mon_pid);
            return;
        }
    }
 
    pid_t pid = fork();
    if (pid < 0) {
        perror("hub: fork hub_mon");
        return;
    }
    if (pid == 0) {
        // copil => hub_mon
        run_hub_mon();
        exit(0);
    }
 
    // parinte => retinem pid-ul hub_mon
    hub_mon_pid = pid;
    printf("[hub] hub_mon pornit cu PID=%d.\n", hub_mon_pid);
}

void cmd_calculate_scores(char districts[][64], int count) {
    if (count == 0) {
        printf("[hub] niciun district specificat.\n");
        return;
    }

    int pipes[MAX_DISTRICTS][2];
    pid_t pids[MAX_DISTRICTS];

    // pornim cate un scorer per district
    for (int i = 0; i < count; i++) {
        if (pipe(pipes[i]) < 0) {
            perror("hub: pipe scorer");
            continue;
        }

        pids[i] = fork();
        if (pids[i] < 0) {
            perror("hub: fork scorer");
            continue;
        }

        if (pids[i] == 0) {
            // copil => scorer, stdout -> pipe
            close(pipes[i][0]);
            dup2(pipes[i][1], STDOUT_FILENO);
            close(pipes[i][1]);

            execlp("./scorer", "scorer", districts[i], NULL);
            perror("hub: exec scorer");
            exit(1);
        }

        // parinte => inchidem capatul de scriere
        close(pipes[i][1]);
    }

    // colectam outputul de la toti scorerii
    printf("\n=== Raport workload ===\n");
    for (int i = 0; i < count; i++) {
        char line[BUF_SIZE];
        int j = 0;
        char c;

        while (read(pipes[i][0], &c, 1) == 1) {
            if (c == '\n' || j == BUF_SIZE - 2) {
                line[j] = '\0';
                j = 0;
                if (strlen(line) == 0) break; // linie goala => scorer terminat
                printf("  %s\n", line);
            } else {
                line[j++] = c;
            }
        }
        close(pipes[i][0]);
        waitpid(pids[i], NULL, 0);
    }
    printf("======================\n");
}

//bucla main
void parse_and_run(char *input) {
    input[strcspn(input, "\n")] = '\0';
 
    if (strcmp(input, "start_monitor") == 0) {
        cmd_start_monitor();
        return;
    }
    if (strncmp(input, "calculate_scores", 16) == 0) {
        char districts[MAX_DISTRICTS][64];
        int count = 0;
 
        // parsam districtele din restul liniei
        char *token = strtok(input + 16, " ");
        while (token && count < MAX_DISTRICTS) {
            strncpy(districts[count], token, 63);
            districts[count][63] = '\0';
            count++;
            token = strtok(NULL, " ");
        }
        cmd_calculate_scores(districts, count);
        return;
    }
 
    if (strcmp(input, "stop_monitor") == 0) {
        pid_t mon_pid = read_monitor_pid();
        if (mon_pid < 0) {
            printf("[hub] niciun monitor activ.\n");
            return;
        }
        if (kill(mon_pid, SIGINT) == 0) {
            printf("[hub] SIGINT trimis monitorului (PID=%d).\n", mon_pid);
        } else {
            perror("[hub] kill monitor");
        }
        return;
    }
 
    if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
        // oprim si monitorul daca e pornit
        pid_t mon_pid = read_monitor_pid();
        if (mon_pid > 0) kill(mon_pid, SIGINT);
        printf("[hub] iesire.\n");
        exit(0);
    }
 
    if (strcmp(input, "help") == 0) {
        printf("comenzi disponibile:\n");
        printf("  start_monitor\n");
        printf("  stop_monitor\n");
        printf("  calculate_scores <district1> <district2> ...\n");
        printf("  exit / quit\n");
        return;
    }
 
    printf("[hub] comanda necunoscuta: %s\n", input);
}

int main(void) {
    printf("[city_hub]\n");
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
 
        // curatam fara sa blocam
        waitpid(-1, NULL, WNOHANG);
    }
    return 0;
}