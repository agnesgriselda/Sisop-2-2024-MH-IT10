#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <curl/curl.h>
#include <zip.h>
#include <libgen.h>
#include <dirent.h>
#include <time.h>

volatile sig_atomic_t current_mode = 0; // Menyimpan mode operasi saat ini
volatile sig_atomic_t shutdown_requested = 0; // Flag untuk shutdown yang aman

// Mendemonisasi proses
static void skeleton_daemon() {
    pid_t pid;
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

// Penanganan sinyal untuk shutdown dan pergantian mode
void handle_signal(int signal) {
    switch (signal) {
        case SIGRTMIN: current_mode = 0; break;
        case SIGUSR1: current_mode = 1; break;
        case SIGUSR2: current_mode = 2; break;
    }
}

void shutdown_handler(int sig) {
    shutdown_requested = 1;
}

void setup_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGRTMIN, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sa.sa_handler = shutdown_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

// Fungsi untuk menulis log
void write_log(const char* filename, const char* action) {
    FILE* log_fp = fopen("history.log", "a");
    if (!log_fp) {
        perror("Failed to open log file");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_struct = localtime(&now);
    char *username = getenv("USER");
    if (!username) username = "unknown";
    fprintf(log_fp, "[%s][%02d:%02d:%02d] - %s - %s\n",
            username,
            tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec,
            filename, action);
    fclose(log_fp);
}

// Enkripsi nama file dengan ROT19
void rot19_filename(char *filename) {
    for (int i = 0; filename[i] != '\0'; i++) {
        filename[i] = rot19_char(filename[i]);
    }
}

char rot19_char(char c) {
    if ((c >= 'a' && c <= 'z')) return 'a' + (c - 'a' + 19) % 26;
    else if ((c >= 'A' && c <= 'Z')) return 'A' + (c - 'A' + 19) % 26;
    else return c;
}

// Fungsi untuk mengunduh file menggunakan libcurl
void download_file(const char *url, const char *output_filename) {
    CURL *curl;
    FILE *fp;
    CURLcode res;
    curl = curl_easy_init();
    if (curl) {
        fp = fopen(output_filename, "wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

// Fungsi untuk menangani file berdasarkan kode khusus
void handle_file_based_on_code(char *path, char *filename, int file_index) {
    char new_path[1024];
    char *action = "";

    if (file_index >= 6) {
        rot19_filename(filename);
        sprintf(new_path, "%s/%s", dirname(path), filename);
    } else {
        strcpy(new_path, path);
    }

    if (strstr(filename, "d3Let3")) {
        remove(new_path);
        action = "Successfully deleted.";
    } else if (strstr(filename, "r3N4mE")) {
        char *ext = strrchr(filename, '.');
        if (ext) {
            if (strcmp(ext, ".ts") == 0) {
                sprintf(new_path, "%s/helper.ts", dirname(path));
            } else if (strcmp(ext, ".py") == 0) {
                sprintf(new_path, "%s/calculator.py", dirname(path));
            } else if (strcmp(ext, ".go") == 0) {
                sprintf(new_path, "%s/server.go", dirname(path));
            } else {
                sprintf(new_path, "%s/renamed.file", dirname(path));
            }
        } else {
            sprintf(new_path, "%s/renamed.file", dirname(path));
        }
        rename(path, new_path);
        action = "Successfully renamed.";
    } else if (strstr(filename, "m0V3")) {
        if (current_mode == 1) {
            sprintf(new_path, "%s/backup/%s", dirname(path), filename);
            rename(path, new_path);
            action = "Successfully moved to backup.";
        } else if (current_mode == 2) {
            sprintf(new_path, "%s/%s", dirname(path), filename);
            rename(path, new_path);
            action = "Successfully restored from backup.";
        }
    }

    if (strlen(action) > 0) {
        write_log(filename, action);
    }
}

// Fungsi untuk mengekstrak file dan menangani berdasarkan konvensi penamaan
int unzip_and_handle_files(const char *zip_filename, const char *output_folder) {
    int err = 0;
    struct zip *z = zip_open(zip_filename, 0, &err);
    struct zip_file *zf;
    struct zip_stat st;
    char buf[1024];
    char file_path[1024];

    if (z) {
        for (int i = 0; i < zip_get_num_entries(z, 0); i++) {
            zip_stat_index(z, i, 0, &st);

            sprintf(file_path, "%s/%s", output_folder, st.name);
            zf = zip_fopen_index(z, i, 0);
            if (zf) {
                FILE *fp = fopen(file_path, "wb");
                while (zip_fread(zf, buf, sizeof(buf)) > 0) {
                    fwrite(buf, sizeof(buf), 1, fp);
                }
                fclose(fp);
                zip_fclose(zf);

                handle_file_based_on_code(file_path, st.name, i);
            }
        }
        zip_close(z);
    }
    return 0;
}

// Fungsi utama program
int main(int argc, char *argv[]) {
    skeleton_daemon();
    setup_signal_handlers();

    const char *directory = "/path/to/directory";
    const char *url = "https://drive.google.com/uc?export=download&id=1rUIZmp10lXLtCIH3LAZJzRPeRks3Crup";
    const char *download_path = "/tmp/downloaded.zip";

    while (!shutdown_requested) {
        sleep(1);  // Memeriksa setiap detik
        if (current_mode == 0) {
            download_file(url, download_path);
            unzip_and_handle_files(download_path, directory);
        }
    }

    printf("Shutting down safely...\n");
    return 0;
}

