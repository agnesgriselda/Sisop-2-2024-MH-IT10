#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>

#define MAX_PATH_LENGTH 512
#define MAX_FILE_LENGTH 1024
#define LOG_FILE "virus.log"

void CustomStringReplace(char *str, const char *old, const char *new) {
    char *pos, temp[MAX_FILE_LENGTH];
    int index = 0;
    int oldLen = strlen(old);
    int newLen = strlen(new);

    while ((pos = strstr(str, old)) != NULL) {
        strcpy(temp, str);
        index = pos - str;
        str[index] = '\0';
        strcat(str, new);
        strcat(str, temp + index + oldLen);
    }
}

void CustomLog(const char *filename, const char *ReplacedString) {
    time_t current_time;
    struct tm *local_time;
    char timeString[20];

    FILE *logFile = fopen(LOG_FILE, "a");
    if (logFile == NULL) {
        perror("Error opening log file");
        exit(EXIT_FAILURE);
    }

    time(&current_time);
    local_time = localtime(&current_time);
    strftime(timeString, sizeof(timeString), "%d-%m-%Y %H:%M:%S", local_time);

    fprintf(logFile, "[%s] Suspicious String at %s successfully replaced!\n", timeString, filename);
    fclose(logFile);
}

void ScanAndReplace(const char *path) {
    struct stat fileStat;
    char FilePath[MAX_PATH_LENGTH];
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(path)) == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        snprintf(FilePath, sizeof(FilePath), "%s/%s", path, entry->d_name);
        
        if (stat(FilePath, &fileStat) < 0) {
            perror("Error stating file");
            exit(EXIT_FAILURE);
        }

        if (S_ISDIR(fileStat.st_mode)) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            ScanAndReplace(FilePath);
        } else {
            FILE *file = fopen(FilePath, "r+");
            if (file == NULL) {
                perror("Error opening file");
                exit(EXIT_FAILURE);
            }

            char FileContent[MAX_FILE_LENGTH];
            while (fgets(FileContent, sizeof(FileContent), file) != NULL) {
                if (strstr(FileContent, "3ncrYp73DStr1nG") != NULL) {
                    CustomStringReplace(FileContent, "3ncrYp73DStr1nG", "[ENCRYPTED_STRING]");
                    fputs(FileContent, file);
                    CustomLog(FilePath, "3ncrYp73DStr1nG");
                }
                // Add more custom string checks here
            }
            fclose(file);
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <folder_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    daemon(1, 0);

    while (1) {
        ScanAndReplace(argv[1]);
        sleep(15);
    }

    return 0;
}

