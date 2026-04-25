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

static void mode_to_str(mode_t m, char out[10])
{
  out[0] = (m & S_IRUSR) ? 'r' : '-';   // owner poate citi?
  out[1] = (m & S_IWUSR) ? 'w' : '-';   // owner poate scrie?     
  out[2] = (m & S_IXUSR) ? 'x' : '-';   // owner poate executa?   
  out[3] = (m & S_IRGRP) ? 'r' : '-';   // grup poate citi?       
  out[4] = (m & S_IWGRP) ? 'w' : '-';   // grup poate scrie?     
  out[5] = (m & S_IXGRP) ? 'x' : '-';   // grup poate executa?    
  out[6] = (m & S_IROTH) ? 'r' : '-';   // altii pot citi?        
  out[7] = (m & S_IWOTH) ? 'w' : '-';   // altii pot scrie?       
  out[8] = (m & S_IXOTH) ? 'x' : '-';   // altii pot executa?     
  out[9] = '\0';
}

static int check_permissions(const char *path, mode_t expected_octal, const char *label)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        perror(label);
        return 0;
    }

    //extragem doar cei 9 biti de permisiune
    mode_t actual = st.st_mode & 0777;

    //convertim ambele valori in forma simbolica cu mode_to_str
    char actual_str[10];
    char expected_str[10];
    mode_to_str(actual, actual_str);
    mode_to_str(expected_octal, expected_str);

    //comparam cele doua seturi de permisiuni
    if (strcmp(actual_str, expected_str) != 0) {
        printf("Eroare permisiuni pentru %s (%s):\n", label, path);
        printf("  Gasit:   %s (0%o)\n", actual_str, actual);
        printf("  Dorit:   %s (0%o)\n", expected_str, expected_octal);
        return 0;
    }

    return 1;
}

// scrie o linie in logged_district dupa fiecare operatie
// format: "timestamp   user   role   operatie"
// 0644 = owner scrie, toti ceilalti doar citesc
void log_action(const char *district_id, const char *username, const char *role, const char *operation) {
    char filepath[100];
    sprintf(filepath, "%s/logged_district", district_id);

    //cream fisierul daca nu exista
    int fd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) { perror("Eroare deschidere logged_district"); return; }
    close(fd);

    //fortam permisiunile corecte
    chmod(filepath, 0644);

    //verificam
    if (!check_permissions(filepath, 0644, "logged_district")) {
        printf("Permisiunile lui logged_district nu sunt corecte.\n");
        return;
    }

    //daca rolul e inspector, nu are voie sa scrie
    //spec doar manager poate scrie
    if (strcmp(role, "inspector") == 0) {
        printf("inspector nu poate scrie in logged_district.\n");
        return;
    }

    //deschidem pentru append si scriem logul
    fd = open(filepath, O_WRONLY | O_APPEND);
    if (fd < 0) { perror("Eroare scriere logged_district"); return; }

    char buf[256];
    int len = sprintf(buf, "%ld\t%s\t%s\t%s\n", (long)time(NULL), username, role, operation);
    write(fd, buf, len);
    close(fd);
}

//cream district.cfg daca nu exista inca
//0640 = owner citeste/scrie, grup doar citeste, altii nimic
void ensure_district_cfg(const char *district_id) {
    char filepath[100];
    sprintf(filepath, "%s/district.cfg", district_id);

    // O_EXCL face ca open sa esueze daca fisierul exista deja
    int fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0640);
    if (fd < 0) return; // exista deja, nu facem nimic

    // scriem valoarea implicita a pragului
    char buf[64];
    int len = sprintf(buf, "threshold=1\n");
    write(fd, buf, len);
    close(fd);

    // fortam permisiunile
    chmod(filepath, 0640);
}

// creaza symlink "active_reports-<district_id>" -> "<district_id>/reports.dat"
// lstat() se opreste la link, stat() il urmareste (pentru dangling)
void create_symlink(const char *district_id) {
    char link_name[64];
    char target[100];
    sprintf(link_name, "active_reports-%s", district_id);
    sprintf(target, "%s/reports.dat", district_id);

    struct stat st;
    struct stat lst;

    // daca link-ul exista deja
    if (lstat(link_name, &lst) == 0) {
        // stat() esueaza => destinatia lipseste => dangling
        if (stat(link_name, &st) != 0) {
            printf("warning: %s este un dangling link (destinatia lipseste)\n", link_name);
            // stergem link-ul stricat si il recreem
            unlink(link_name);
            if (symlink(target, link_name) == 0)
                printf("symlink refacut: %s -> %s\n", link_name, target);
        }
        // altfel e valid, nu facem nimic
        return;
    }

    // link-ul nu exista, il cream
    if (symlink(target, link_name) != 0) {
        perror("eroare la crearea symlink");
        return;
    }
    printf("symlink creat: %s -> %s\n", link_name, target);
}

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

    //cream directorul districtului daca nu exista
    struct stat st_dir;
    if (stat(district_id, &st_dir) == -1) {
        if (mkdir(district_id, 0750) == -1) {
            perror("Eroare la crearea directorului districtului");
            return;
        }

	//fortam permisiunile
        chmod(district_id, 0750);
    }

    //verificam 
    if (!check_permissions(district_id, 0750, "director district")) {
        printf("Permisiunile directorului nu sunt corecte. Operatia este anulata.\n");
        return;
    }

    // cream district.cfg cu valoarea implicita daca nu exista inca
    ensure_district_cfg(district_id);

    //determinam calea pentru reports.dat
    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);
    uint32_t next_id = get_next_report_id(filepath);

    //cream sau deschidem fisierul reports.dat 
    int fd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0664);
    if (fd < 0) {
        perror("Eroare la deschiderea fisierului");
        return;
    }
    close(fd);

    //fortam
    chmod(filepath, 0664);

    //verificam
    if (!check_permissions(filepath, 0664, "reports.dat")) {
        printf("Permisiunile fisierului nu sunt corecte. Operatia este anulata.\n");
        return;
    }

    //redeschdem pentru scriere si adaugam raportul 
    fd = open(filepath, O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("Eroare la redeschiderea fisierului pentru scriere");
        return;
    }

    srand(time(NULL));
    Report new_report;
    new_report.report_id = next_id;
    strncpy(new_report.inspector_name, username, 31);
    new_report.inspector_name[31] = '\0';
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
    log_action(district_id, Arguments.username, Arguments.role, "add");

    create_symlink(district_id);
}

void list_reports(const char *district_id) {
    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    //verificam daca poate intra
    if (!check_permissions(filepath, 0664, "reports.dat")) {
        printf("Permisiunile fisierului nu permit listarea.\n");
        return;
    }

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Eroare la deschiderea fisierului pentru listare");
        return;
    }

    //afisam despre fisier
    struct stat st;
    if (fstat(fd, &st) == 0) {
        char perm_str[10];
        mode_to_str(st.st_mode & 0777, perm_str); 

        char mtime_str[26];
        struct tm *tm_info = localtime(&st.st_mtime);
        strftime(mtime_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);

        printf("Fisier: %s\n", filepath);
        printf("Permisiuni: %s | Dimensiune: %ld bytes | Ultima modificare: %s\n",
               perm_str, (long)st.st_size, mtime_str);
    }

    Report r;
    printf("Raportele din districtul %s:\n", district_id);
    printf("------------------------------------------------------------\n");
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        char time_str[26];
        time_t temp_timestamp = r.timestamp;
        struct tm *tm_info = localtime(&temp_timestamp);
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

    //verificam perms
    if (!check_permissions(filepath, 0664, "reports.dat")) {
        printf("Permisiunile fisierului nu permit vizualizarea.\n");
        return;
    }

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) { perror("Eroare deschidere"); return; }

    uint32_t target_id = (uint32_t)strtol(report_id_str, NULL, 10);
    Report r;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (r.report_id == target_id) {
            char time_str[26];
            time_t temp_timestamp = r.timestamp;
            struct tm *tm_info = localtime(&temp_timestamp);
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
    printf("Raportul %u nu a fost gasit.\n", target_id);
    close(fd);
}

void remove_report(const char *district_id, const char *report_id_str) {
    //verificam daca e manager
    if (strcmp(Arguments.role, "manager") != 0) {
        printf("Permisiune refuzata. Doar managerul poate sterge rapoarte.\n");
        return;
    }

    char filepath[100];
    sprintf(filepath, "%s/reports.dat", district_id);

    //verificam 
    if (!check_permissions(filepath, 0664, "reports.dat")) {
        printf("Permisiunile fisierului nu permit stergerea.\n");
        return;
    }

    int fd = open(filepath, O_RDWR);
    if (fd < 0) { perror("Eroare deschidere"); return; }

    struct stat st;
    fstat(fd, &st);
    long num_records = st.st_size / sizeof(Report);
    uint32_t target_id = (uint32_t)strtol(report_id_str, NULL, 10);

    //cautam index
    long del_idx = -1;
    Report r;
    for (long i = 0; i < num_records; i++) {
        lseek(fd, i * sizeof(Report), SEEK_SET);
        read(fd, &r, sizeof(Report));
        if (r.report_id == target_id) { del_idx = i; break; }
    }

    if (del_idx == -1) {
        printf("Raportul %u nu a fost gasit.\n", target_id);
        close(fd); return;
    }

    //mutam toate inregistrarile de dupa del_idx cu o pozitie inapoi
    for (long i = del_idx + 1; i < num_records; i++) {
        lseek(fd, i * sizeof(Report), SEEK_SET);
        read(fd, &r, sizeof(Report));
        lseek(fd, (i - 1) * sizeof(Report), SEEK_SET);
        write(fd, &r, sizeof(Report));
    }

    //trunchiem fisierul pentru a elimina ultima inregistrare (duplicata)
    ftruncate(fd, (num_records - 1) * sizeof(Report));
    close(fd);
    printf("Raportul %u a fost sters.\n", target_id);
    log_action(district_id, Arguments.username, Arguments.role, "remove_report");
}

void update_threshold(const char *district_id, int value) {
    //doar manager
    if (strcmp(Arguments.role, "manager") != 0) {
        printf("Permisiune refuzata. Doar managerul poate actualiza pragul.\n");
        return;
    }

    char filepath[100];
    sprintf(filepath, "%s/district.cfg", district_id);

    //cream fisierul daca nu exista, cu permisiunile corecte
    int fd_check = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0640);
    if (fd_check >= 0) {
        close(fd_check);
        chmod(filepath, 0640);  //fortam
    }

    //verificam
    if (!check_permissions(filepath, 0640, "district.cfg")) {
        printf("Cineva a modificat permisiunile lui district.cfg! Operatia este refuzata.\n");
        return;
    }

    int fd = open(filepath, O_WRONLY | O_TRUNC);
    if (fd < 0) { perror("Eroare deschidere district.cfg"); return; }

    char buf[64];
    int len = sprintf(buf, "threshold=%d\n", value);
    write(fd, buf, len);
    close(fd);
    printf("Pragul a fost actualizat la %d in districtul %s.\n", value, district_id);
    log_action(district_id, Arguments.username, Arguments.role, "update_threshold");
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

    //verificam
    if (!check_permissions(filepath, 0664, "reports.dat")) {
        printf("Permisiunile fisierului nu permit filtrarea.\n");
        return;
    }

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) { perror("Eroare deschidere"); return; }

    Report r;
    int found = 0;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        int all_match = 1;
        for (int c = 0; c < Arguments.condition_count; c++) {
            char field[32], op[4], value[64];
            if (!parse_condition(Arguments.conditions[c], field, op, value)) {
                printf("Conditie invalida: %s\n", Arguments.conditions[c]);
                all_match = 0; break;
            }
            if (!match_condition(&r, field, op, value)) {
                all_match = 0; break;
            }
        }
        if (all_match) {
            char time_str[26];
            time_t temp_timestamp = r.timestamp;
            strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", localtime(&temp_timestamp));
            printf("ID: %u | Inspector: %s | Cat: %s | Sev: %u | %s\n",
                   r.report_id, r.inspector_name, r.category, r.severity, time_str);
            found++;
        }
    }
    if (!found) printf("Niciun raport nu corespunde conditiilor.\n");
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