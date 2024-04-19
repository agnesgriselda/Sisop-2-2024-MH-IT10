#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#define MAX_ARGS 10
#define LOG_FILE_EXTENSION ".log"

void monitor_process(char *user) {
    pid_t child_pid;
    int status;

    child_pid = fork();
    if (child_pid < 0) {
        perror("Error in fork");
        exit(EXIT_FAILURE);
    } else if (child_pid == 0) {
        // Child process
        char *args[] = {"ps", "-U", user, NULL};
        execv("/bin/ps", args);
        perror("execv");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        waitpid(child_pid, &status, 0);
    }
}
void stop_monitoring(char *user) {
    // Membuat nama file PID daemon
    char pid_filename[50];
    snprintf(pid_filename, sizeof(pid_filename), "%s%s", user, ".pid");

    // Membuka file PID daemon
    FILE *pid_file = fopen(pid_filename, "r");
    if (pid_file == NULL) {
        printf("Daemon process is not running for user %s\n", user);
        return;
    }

    // Membaca PID daemon
    pid_t daemon_pid;
    fscanf(pid_file, "%d", &daemon_pid);
    fclose(pid_file);

    // Mengirim sinyal SIGTERM ke daemon untuk menghentikannya
    if (kill(daemon_pid, SIGTERM) == -1) {
        perror("Error sending SIGTERM to daemon");
        return;
    }

    printf("Monitoring stopped for user %s\n", user);
}
void block_processes(char *user) {
    // Membuat nama file daftar blokir
    char blocklist_filename[50];
    snprintf(blocklist_filename, sizeof(blocklist_filename), "%s%s", user, ".blocklist");

    // Membuka file daftar blokir
    FILE *blocklist_file = fopen(blocklist_filename, "w");
    if (blocklist_file == NULL) {
        perror("Error opening blocklist file");
        return;
    }

    // Menulis pesan bahwa proses diblokir ke dalam file
    fprintf(blocklist_file, "All processes blocked for user %s\n", user);

    // Menutup file daftar blokir
    fclose(blocklist_file);

    printf("All processes blocked for user %s\n", user);
}
void unblock_processes(char *user) {
    // Membuat nama file daftar blokir
    char blocklist_filename[50];
    snprintf(blocklist_filename, sizeof(blocklist_filename), "%s%s", user, ".blocklist");

    // Menghapus file daftar blokir
    if (remove(blocklist_filename) == -1) {
        perror("Error removing blocklist file");
        return;
    }

    printf("All processes unblocked for user %s\n", user);
}
void log_process(char *user, pid_t pid, char *process_name, int status) {
    // Membuat string timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "[%d:%m:%Y]-[%H:%M:%S]", tm_info);

    // Membuat nama file log berdasarkan nama pengguna
    char log_filename[50];
    snprintf(log_filename, sizeof(log_filename), "%s%s%s", user, ".log", timestamp);

    // Membuka file log
    FILE *log_file = fopen(log_filename, "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    // Menuliskan entri log ke dalam file
    fprintf(log_file, "%s-%d-%s-%s\n", timestamp, pid, process_name, (status == 0) ? "JALAN" : "GAGAL");

    // Menutup file log
    fclose(log_file);
}
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <options> <user>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *user = argv[argc - 1]; // Mengambil nama pengguna dari argumen terakhir

    // Memeriksa opsi yang diberikan dan memanggil fungsi yang sesuai
    if (strcmp(argv[1], "-m") == 0) {
        monitor_process(user);
    } else if (strcmp(argv[1], "-s") == 0) {
        stop_monitoring(user);
    } else if (strcmp(argv[1], "-c") == 0) {
        block_processes(user);
    } else if (strcmp(argv[1], "-a") == 0) {
        unblock_processes(user);
    } else {
        printf("Invalid option\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
