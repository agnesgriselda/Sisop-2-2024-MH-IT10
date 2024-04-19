#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_APPS 10
#define MAX_NAME_LENGTH 50

void launch_apps(char *apps[], int *instances, int count);
void load_configuration(char *config_file);
void terminate_all_apps();
void terminate_apps_from_config(char *config_file);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [-l <app1> <num1> <app2> <num2> ... <appN> <numN>] [-c <config_file>] [-t]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-l") == 0) {
        int num_apps = (argc - 2) / 2;
        char *apps[MAX_APPS];
        int instances[MAX_APPS];

        for (int i = 0; i < num_apps; i++) {
            apps[i] = argv[i * 2 + 2];
            instances[i] = atoi(argv[i * 2 + 3]);
        }

        launch_apps(apps, instances, num_apps);
    } else if (strcmp(argv[1], "-c") == 0) {
        if (argc != 3) {
            printf("Usage: %s -c <config_file>\n", argv[0]);
            return 1;
        }
        load_configuration(argv[2]);
    } else if (strcmp(argv[1], "-t") == 0) {
        if (argc == 3 && strcmp(argv[2], "-c") == 0) {
            if (argc != 4) {
                printf("Usage: %s -t <config_file>\n", argv[0]);
                return 1;
            }
            terminate_apps_from_config(argv[3]);
        } else {
            terminate_all_apps();
        }
    } else {
        printf("Invalid option: %s\n", argv[1]);
        return 1;
    }

    return 0;
}

void launch_apps(char *apps[], int *instances, int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < instances[i]; j++) {
            pid_t pid = fork();
            if (pid == 0) {
                execlp(apps[i], apps[i], NULL);
                exit(0);
            } else if (pid < 0) {
                printf("Error: Fork failed\n");
            }
        }
    }
}

void load_configuration(char *config_file) {
    FILE *file = fopen(config_file, "r");
    if (file == NULL) {
        printf("Error: Cannot open file %s\n", config_file);
        return;
    }

    printf("Reading configuration from file %s:\n", config_file);

    char app[MAX_NAME_LENGTH];
    int num;

    while (fscanf(file, "%s %d", app, &num) == 2) {
        printf("Launching %d instances of %s\n", num, app);
        for (int i = 0; i < num; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                execlp(app, app, NULL);
                exit(0);
            } else if (pid < 0) {
                printf("Error: Fork failed\n");
            }
        }
    }

    fclose(file);
}

void terminate_all_apps() {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("killall", "killall", "firefox", NULL);
        exit(0);
    } else if (pid < 0) {
        printf("Error: Fork failed\n");
    } else {
        wait(NULL);
    }

    pid = fork();
    if (pid == 0) {
        execlp("killall", "killall", "wireshark", NULL);
        exit(0);
    } else if (pid < 0) {
        printf("Error: Fork failed\n");
    } else {
        wait(NULL);
    }
    // Add more applications as needed
}

void terminate_apps_from_config(char *config_file) {
    FILE *file = fopen(config_file, "r");
    if (file == NULL) {
        printf("Error: Cannot open file %s\n", config_file);
        return;
    }

    char app[MAX_NAME_LENGTH];
    while (fscanf(file, "%s", app) == 1) {
        pid_t pid = fork();
        if (pid == 0) {
            execlp("killall", "killall", app, NULL);
            exit(0);
        } else if (pid < 0) {
            printf("Error: Fork failed\n");
        } else {
            wait(NULL);
        }
    }

    fclose(file);
}

