#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define PID_FILE ".monitor_pid"

//volatile => compilator nu o cache-uieste
static volatile sig_atomic_t should_exit = 0;

void handle_sigusr1(int sig) {
    (void)sig; //evitam warning de parametru nefolosit
    printf("monitor: raport nou adaugat.\n");
    fflush(stdout); //fortam afisarea imediat nu asteptam sa se gate
}

void handle_sigint(int sig) {
    (void)sig;
    should_exit = 1;
}

void write_pid_file() 
{
    //deschidem calea catre fisier
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("eroare la crearea .monitor_pid");
        exit(1);
    }

    char aux[32];
    int len = sprintf(aux, "%d\n", getpid());
    write(fd, aux, len);
    close(fd);
}

//stergem .monitor_pid la inchidere
void delete_pid_file() {
    if (unlink(PID_FILE) != 0) 
    {
        perror("eroare la stergerea .monitor_pid");
    }
}

int main(void) 
{
    struct sigaction sa_usr1;
    sa_usr1.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);  
    sa_usr1.sa_flags = 0;           
    if (sigaction(SIGUSR1, &sa_usr1, NULL) == -1) {
        perror("eroare sigaction SIGUSR1");
        exit(1);
    }
 
    struct sigaction sa_int;
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("eroare sigaction SIGINT");
        exit(1);
    }

    //cream pid-file
    write_pid_file();
    printf("monitorizare pornita cu PID-ul %d\n", getpid());
    fflush(stdout);

    // bucla principala => pana should_exit devine 1
    while (should_exit==0) {
        pause();
    }

    // am primit SIGINT
    printf("monitorizare: SIGINT primit, oprire.\n");
    //stergem pid cand se opreste monitorizarea
    delete_pid_file();
    return 0;
}