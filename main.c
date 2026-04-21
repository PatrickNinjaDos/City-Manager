#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct arguments {
    char role[20];
    char username[20];
    char operation[20];
    char district_id[20];
    char report_id[20];
    int value;
    char conditions[10][64];
    int condition_count;
}arguments;
arguments Arguments;

typedef struct {
    uint32_t report_id;
    char inspector_name[32];
    float latitude;
    float longitude;
    char category[32];
    uint32_t severity;
    time_t timestamp;
    char description[128];
}__attribute__((packed)) Report;

/*
__attribute__((packed))
=> Eliminarea spatiilor goale (padding) dintre campurile structurii pentru
a garanta ca dimensiunea si asezarea datelor in fisierul binar raman identice
cu cele din memorie, indiferent de sistem sau compilator.
*/

void parse_arguments(int argc,char *argv[]) {
    bool role_set = false, user_set = false, op_set = false;
    memset(&Arguments, 0, sizeof(Arguments));

    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i],"--role")==0 && i+1<argc) {
            strcpy(Arguments.role,argv[++i]);
            role_set = true;
        }
        else if (strcmp(argv[i],"--user")==0 && i+1<argc) {
            strcpy(Arguments.username,argv[++i]);
            user_set = true;
        }
        else if ((strcmp(argv[i], "--add")==0 || strcmp(argv[i], "--list")==0) && i+1<argc) {
            strcpy(Arguments.operation, argv[i]);
            strcpy(Arguments.district_id, argv[++i]);
            op_set = true;
        }
        else if ((strcmp(argv[i], "--remove_report")==0 || strcmp(argv[i], "--view")==0) && i+2<argc) {
            strcpy(Arguments.operation, argv[i]);
            strcpy(Arguments.district_id, argv[++i]);
            strcpy(Arguments.report_id, argv[++i]);
            op_set = true;
        }
        else if (strcmp(argv[i], "--update_threshold")==0 && i+2<argc) {
            strcpy(Arguments.operation, argv[i]);
            strcpy(Arguments.district_id, argv[++i]);
            Arguments.value = strtol(argv[++i],NULL,10);
            op_set = true;
        }
        else if (strcmp(argv[i], "--filter") == 0 && i + 2 < argc) {
            strcpy(Arguments.operation, argv[i]);
            strcpy(Arguments.district_id, argv[++i]);
            Arguments.condition_count = 0;

            while (i + 1 < argc && argv[i+1][0] != '-') {
                strcpy(Arguments.conditions[Arguments.condition_count++], argv[++i]);
            }
            op_set = true;
        }
    }

    if (role_set==false || user_set==false || op_set==false){
        printf("Wrong input");
        exit(1);
    }

    //printf("rol:%s si user:%s\n",Arguments.role,Arguments.username);
}

bool is_operation(char *actual_operation,char *target_operation) {
    if (strcmp(actual_operation+2,target_operation)==0) return true;
    else return false;
}

uint32_t get_next_report_id(const char *filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return 1; // fisierul nu exista inca

    struct stat st;
    if (fstat(fd, &st) == -1 || st.st_size == 0) {
        close(fd);
        return 1;
    }

    long num_records = st.st_size / sizeof(Report);
    lseek(fd, (num_records - 1) * sizeof(Report), SEEK_SET);

    Report last_report;
    uint32_t next_id = 1;
    if (read(fd, &last_report, sizeof(Report)) == sizeof(Report)) {
        next_id = last_report.report_id + 1;
    }
    close(fd);
    return next_id;
}

void add_report(const char *district_id, const char *username) {

    //creem un director in cazul in care nu exista
    struct stat st_dir;
    if (stat(district_id, &st_dir) == -1) {
      if (mkdir(district_id) == -1) {
            perror("Eroare la crearea directorului districtului");
            return;
        }
    }

    chmod(district_id,0750);

    //setam calea unde urmeaza sa fie creat fisierul
    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    uint32_t next_id = get_next_report_id(filepath);

    //creem fisierul reports.dat cu permisiunile respective
    int fd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0664);
    if (fd < 0) {
        perror("Eroare la deschiderea fisierului");
        return;
    }

    if (chmod(filepath, 0664) == -1) {
        perror("Eroare la chmod");
    }

    struct stat st;
    if (stat(filepath, &st) == 0) {
        mode_t perm = st.st_mode & 0777;
        //0664 trebuie defapt dar nu merge ???
        if (perm != 0666) {
            printf("Eroare: Permisiuni incorecte!\n");
            printf("Am gasit: 0%3o, Dorim: 0664\n", perm);
            close(fd);
            exit(1);
        }
    }

    srand(time(NULL));
    Report new_report;
    new_report.report_id = next_id;
    strncpy(new_report.inspector_name, username, 31);
    new_report.latitude = ((float)rand()/(float)RAND_MAX) * 100.0f;
    new_report.longitude = ((float)rand()/(float)RAND_MAX) * 100.0f;
    char *categorii[] = {"road", "lighting", "waste", "pollution"};
    strcpy(new_report.category, categorii[rand() % 4]);
    new_report.severity = (rand() % 3) + 1;
    new_report.timestamp = time(NULL);
    sprintf(new_report.description, "Raport generat automat de %s.", username);

    write(fd, &new_report, sizeof(Report));
    close(fd);

    printf("Raport adaugat cu succes in districtul %s.\n", district_id);
}

void list_reports(const char *district_id) {
    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Eroare la deschiderea fișierului pentru listare");
        return;
    }

    Report r;
    printf("Raportele din districtul %s:\n", district_id);
    printf("------------------------------------------------------------\n");
    //citim toate rapoartele
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        char time_str[26];
        struct tm *tm_info = localtime(&r.timestamp);
        strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);

        printf("ID: %u | Inspector: %s | Categorie: %s | Severitate: %u\n",
               r.report_id, r.inspector_name, r.category, r.severity);
        printf("Locatie: %.4f, %.4f | Timp: %s\n", r.latitude, r.longitude, time_str);
        printf("Descriere: %s\n", r.description);
        printf("------------------------------------------------------------\n");
    }

    close(fd);
}

void view_report(const char *district_id, const char *report_id_str) {
    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) { perror("No open"); return; }

    uint32_t target_id = (uint32_t)strtol(report_id_str, NULL, 10);
    Report r;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (r.report_id == target_id) {
            char time_str[26];
            struct tm *tm_info = localtime(&r.timestamp);
            strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
            printf("------------------------------------------------------------\n");
            printf("ID: %u | Inspector: %s | Categorie: %s | Severitate: %u\n",
                   r.report_id, r.inspector_name, r.category, r.severity);
            printf("Locatie: %.4f, %.4f | Timp: %s\n", r.latitude, r.longitude, time_str);
            printf("Descriere: %s\n", r.description);
            printf("------------------------------------------------------------\n");
            close(fd);
            return;
        }
    }
    printf("Report %u not found.\n", target_id);
    close(fd);
}

void remove_report(const char *district_id, const char *report_id_str) {
    if (strcmp(Arguments.role, "manager") != 0) {
        printf("No permission. Manager only.\n");
        return;
    }

    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    int fd = open(filepath, O_RDWR);
    if (fd < 0) { perror("No open"); return; }

    struct stat st;
    fstat(fd, &st);
    long num_records = st.st_size / sizeof(Report);
    uint32_t target_id = (uint32_t)strtol(report_id_str, NULL, 10);

    // find index
    long del_idx = -1;
    Report r;
    for (long i = 0; i < num_records; i++) {
        lseek(fd, i * sizeof(Report), SEEK_SET);
        read(fd, &r, sizeof(Report));
        if (r.report_id == target_id) { del_idx = i; break; }
    }

    if (del_idx == -1) {
        printf("Report %u not found.\n", target_id);
        close(fd); return;
    }

    // shift left — records after del_idx move one slot back
    for (long i = del_idx + 1; i < num_records; i++) {
        lseek(fd, i * sizeof(Report), SEEK_SET);
        read(fd, &r, sizeof(Report));
        lseek(fd, (i - 1) * sizeof(Report), SEEK_SET);
        write(fd, &r, sizeof(Report));
    }

    // chop tail
    ftruncate(fd, (num_records - 1) * sizeof(Report));
    close(fd);
    printf("Report %u removed.\n", target_id);
}

void update_threshold(const char *district_id, int value) {
    if (strcmp(Arguments.role, "manager") != 0) {
        printf("No permission. Manager only.\n");
        return;
    }

    char filepath[100];
    sprintf(filepath, "%s/district.cfg", district_id);

    // creeaza daca nu exista
    int fd_check = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0640);
    if (fd_check >= 0) close(fd_check);

    // verifica permisiuni
    struct stat st;
    stat(filepath, &st);
    if ((st.st_mode & 0777) != 0640) {
        printf("Bad perms on district.cfg. Expected 640, got 0%o\n", st.st_mode & 0777);
        return;
    }

    int fd = open(filepath, O_WRONLY | O_TRUNC);
    if (fd < 0) { perror("No open"); return; }

    char buf[64];
    int len = sprintf(buf, "threshold=%d\n", value);
    write(fd, buf, len);
    close(fd);
    printf("Threshold updated to %d in %s.\n", value, district_id);
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    const char *first = strchr(input, ':');
    if (!first) return 0;
    const char *second = strchr(first + 1, ':');
    if (!second) return 0;

    strncpy(field, input, first - input);
    field[first - input] = '\0';
    strncpy(op, first + 1, second - first - 1);
    op[second - first - 1] = '\0';
    strcpy(value, second + 1);
    return 1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    if (strcmp(field, "severity") == 0) {
        int sev = (int)r->severity;
        int val = atoi(value);
        if (strcmp(op,"==")==0) return sev == val;
        if (strcmp(op,"!=")==0) return sev != val;
        if (strcmp(op,"<")==0)  return sev <  val;
        if (strcmp(op,"<=")==0) return sev <= val;
        if (strcmp(op,">")==0)  return sev >  val;
        if (strcmp(op,">=")==0) return sev >= val;
    }
    if (strcmp(field, "category") == 0) {
        if (strcmp(op,"==")==0) return strcmp(r->category, value)==0;
        if (strcmp(op,"!=")==0) return strcmp(r->category, value)!=0;
    }
    if (strcmp(field, "inspector") == 0) {
        if (strcmp(op,"==")==0) return strcmp(r->inspector_name, value)==0;
        if (strcmp(op,"!=")==0) return strcmp(r->inspector_name, value)!=0;
    }
    if (strcmp(field, "timestamp") == 0) {
        time_t ts = r->timestamp;
        time_t val = (time_t)atol(value);
        if (strcmp(op,"==")==0) return ts == val;
        if (strcmp(op,"!=")==0) return ts != val;
        if (strcmp(op,"<")==0)  return ts <  val;
        if (strcmp(op,"<=")==0) return ts <= val;
        if (strcmp(op,">")==0)  return ts >  val;
        if (strcmp(op,">=")==0) return ts >= val;
    }
    return 0;
}

void filter_reports(const char *district_id) {
    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) { perror("No open"); return; }

    Report r;
    int found = 0;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        int all_match = 1;
        for (int c = 0; c < Arguments.condition_count; c++) {
            char field[32], op[4], value[64];
            if (!parse_condition(Arguments.conditions[c], field, op, value)) {
                printf("Bad condition: %s\n", Arguments.conditions[c]);
                all_match = 0; break;
            }
            if (!match_condition(&r, field, op, value)) {
                all_match = 0; break;
            }
        }
        if (all_match) {
            char time_str[26];
            strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", localtime(&r.timestamp));
            printf("ID: %u | Inspector: %s | Cat: %s | Sev: %u | %s\n",
                   r.report_id, r.inspector_name, r.category, r.severity, time_str);
            found++;
        }
    }
    if (!found) printf("No match.\n");
    close(fd);
}

int main(int argc,char *argv[])
{
    parse_arguments(argc,argv);
    if (is_operation(Arguments.operation,"add")) {
        add_report(Arguments.district_id, Arguments.username);
    }
    else if (is_operation(Arguments.operation,"list")) {
        list_reports(Arguments.district_id);
    }
    else if (is_operation(Arguments.operation, "view")) {
        view_report(Arguments.district_id, Arguments.report_id);
    }
    else if (is_operation(Arguments.operation, "remove_report")) {
        remove_report(Arguments.district_id, Arguments.report_id);
    }
    else if (is_operation(Arguments.operation, "update_threshold")) {
        update_threshold(Arguments.district_id, Arguments.value);
    }
    else if (is_operation(Arguments.operation, "filter")) {
        filter_reports(Arguments.district_id);
    }
    return 0;
}
