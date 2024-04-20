#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_COMMAND_LENGTH 1024

void show_processes(char *user) {
    pid_t pid = fork();
    if (pid == 0) {
        char command[MAX_COMMAND_LENGTH];
        snprintf(command, MAX_COMMAND_LENGTH, "ps -u %s", user);
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
      perror("fork");
      exit(EXIT_FAILURE);
    } else {
      wait(NULL);
    }
}

int check_process_status(int pid) {
    char status_file[MAX_COMMAND_LENGTH];
    snprintf(status_file, MAX_COMMAND_LENGTH, "/proc/%d", pid);
    if (access(status_file, F_OK) != -1) {
        return 1; // Proses sedang berjalan
    } else {
        return 0; // Proses tidak berjalan
    }
}

void monitor_processes(char *user) {
    pid_t pid;
    char log_file[MAX_COMMAND_LENGTH];
    snprintf(log_file, MAX_COMMAND_LENGTH, "%s.log", user);
    FILE *fp = fopen(log_file, "a");
    if (fp == NULL) {
        fprintf(stderr, "Tidak dapat membuka file log %s\n", log_file);
        return;
    }

    while (1) {
        char command[MAX_COMMAND_LENGTH];
        snprintf(command, MAX_COMMAND_LENGTH, "ps -u %s --no-headers -o pid,command", user);
        FILE *pipe = popen(command, "r");
        if (pipe == NULL) {
            fprintf(stderr, "Tidak dapat menjalankan command %s\n", command);
            fclose(fp);
            return;
        }

        char line[MAX_COMMAND_LENGTH];
        time_t current_time = time(NULL);
        struct tm *local_time = localtime(&current_time);
        char timestamp[20];
        char date[11];
        strftime(timestamp, sizeof(timestamp), "%H:%M:%S", local_time);
        strftime(date, sizeof(date), "%d-%m-%Y", local_time);

        while (fgets(line, sizeof(line), pipe)) {
            char pid_str[10], process[MAX_COMMAND_LENGTH];
            sscanf(line, "%s %[^\n]", pid_str, process);
            int pid = atoi(pid_str);
            char status[7] = "JALAN"; // Asumsikan semua proses berjalan dengan baik

            if (!check_process_status(pid)) {
                strcpy(status, "GAGAL"); // Jika proses tidak berjalan, ubah status menjadi GAGAL
            }

            fprintf(fp, "[%s]-[%s]-%d-%s-%s\n", date, timestamp, pid, process, status);
        }

        pclose(pipe);
        sleep(1);
    }

    fclose(fp);
}

void kill_processes(char *user) {
    pid_t pid = fork();
    if (pid == 0) {
        char command[MAX_COMMAND_LENGTH];
        snprintf(command, MAX_COMMAND_LENGTH, "pkill -u %s", user);
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
      perror("fork");
      exit(EXIT_FAILURE);
    } else {
      wait(NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Penggunaan: %s <opsi> <user>\n", argv[0]);
        fprintf(stderr, "Opsi:\n");
        fprintf(stderr, "  -l: Tampilkan proses yang sedang berjalan\n");
        fprintf(stderr, "  -m: Pantau proses yang dijalankan\n");
        fprintf(stderr, "  -s: Hentikan pemantauan proses\n");
        fprintf(stderr, "  -c: Gagalkan proses yang dijalankan secara terus-menerus\n");
        fprintf(stderr, "  -a: Hentikan penggagalan proses\n");
        return 1;
    }

    char *option = argv[1];
    char *user = argv[2];

    if (strcmp(option, "-l") == 0) {
        show_processes(user);
    } else if (strcmp(option, "-m") == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            monitor_processes(user);
            exit(0);
        } else if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        }
    } else if (strcmp(option, "-s") == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            char command[MAX_COMMAND_LENGTH];
            snprintf(command, MAX_COMMAND_LENGTH, "pkill -f 'monitor_processes %s'", user);
            execl("/bin/sh", "sh", "-c", command, NULL);
            perror("execl");
            exit(EXIT_FAILURE);
        } else if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        } else {
            wait(NULL);
        }
    } else if (strcmp(option, "-c") == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            while (1) {
                kill_processes(user);
                sleep(1);
            }
            exit(0);
        } else if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        }
    } else if (strcmp(option, "-a") == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            char command[MAX_COMMAND_LENGTH];
            snprintf(command, MAX_COMMAND_LENGTH, "pkill -f 'kill_processes %s'", user);
            execl("/bin/sh", "sh", "-c", command, NULL);
            perror("execl");
            exit(EXIT_FAILURE);
        } else if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        } else {
            wait(NULL);
        }
    } else {
        fprintf(stderr, "Opsi tidak valid\n");
        return 1;
    }

    return 0;
}
