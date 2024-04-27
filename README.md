# Modul 2
## *Process* dan Daemon

- Agnes Zenobia __Griselda__ Petrina (5027231034)
- Muhammad __Nafi__ Firdaus (5027231045)
- __Rafika__ Az Zahra Kusumastuti (5027231050)


## Soal 1

Gavriel adalah seorang cyber security enthusiast. Suatu hari, ia dikontrak oleh sebuah perusahaan ternama untuk membuat sebuah program yang cukup rumit dengan bayaran jutaan rupiah. Karena tergoda dengan nominal bayaran tersebut, Gavriel langsung menerima tawaran tersebut. Setelah mencoba membuat dan mengembangkan program tersebut selama seminggu, laptop yang digunakan Gavriel mengalami overheat dan mati total sehingga harus dilarikan ke tukang servis terdekat. Karena keterbatasan waktu dalam pembuatan program dan tidak ingin mengecewakan perusahaan, Gavriel meminta bantuan kalian untuk membuat program tersebut dengan ketentuan sebagai berikut:

a. Program dapat menerima input path berupa ‘argv’ untuk mengatur folder dimana file akan dieksekusi

b. Program tersebut berfungsi untuk mereplace string dengan ketentuan sebagai berikut: 
  - String m4LwAr3 direplace dengan string [MALWARE]
  - String 5pYw4R3 direplace dengan string [SPYWARE]
  - String R4nS0mWaR3 direplace dengan string [RANSOMWARE]

c. Program harus berjalan secara daemon, dan tidak diperbolehkan menggunakan command system() dalam pembuatan program

d. Program akan secara terus menerus berjalan di background dengan jeda 15 detik

e. Catat setiap penghapusan string yang dilakukan oleh program pada sebuah file bernama virus.log dengan format: [dd-mm-YYYY][HH:MM:SS] Suspicious string at <file_name> successfully replaced!

Contoh penggunaan: ./virus /home/user/virus

Contoh isi file sebelum program dijalankan:
pU=-JWQ$5$)D-[??%AVh]$cB6bm4LwAr3jEQC2p3R{HV]=-AUaxj:Qe+h
!aNX,i:!z3W=2;.tHc3&S+}6F)CFf%tfZLP1*w5m1PAzZJUux(
Pd&f8$F5=E?@#[6jd{TJKj]5pYw4R3{KK1?hz384$ge@iba5GAj$gqB41
#C&&a}M9C#f64Eb.?%c)dGbCvJXtU[?SE4h]BY4e1PR4nS0mWaR3{]S/{w?*


Contoh isi file setelah setelah program dijalankan:
pU=-JWQ$5$)D-[??%AVh]$cB6b[MALWARE]jEQC2p3R{HV]=-AUaxj:Qe+h
!aNX,i:!z3W=2;.tHc3&S+}6F)CFf%tfZLP1*w5m1PAzZJUux(
Pd&f8$F5=E?@#[6jd{TJKj][SPYWARE]{KK1?hz384$ge@iba5GAj$gqB41
#C&&a}M9C#f64Eb.?%c)dGbCvJXtU[?SE4h]BY4e1P[RANSOMWARE]{]S/{w?*

Tentu, di bawah ini adalah penjelasan mengenai kode yang diberikan:

### Virus.c Penjelasan

1. **Include Libraries**: Program dimulai dengan menyertakan beberapa pustaka standar seperti `<stdio.h>`, `<stdlib.h>`, dan lainnya yang dibutuhkan untuk operasi file dan waktu.

2. **Makro dan Konstanta**: `MAX_PATH_LENGTH`, `MAX_FILE_LENGTH`, dan `LOG_FILE` didefinisikan. Ini adalah batasan panjang untuk path file, panjang file, dan nama file log.

   ```c
   #define MAX_PATH_LENGTH 512
   #define MAX_FILE_LENGTH 1024
   #define LOG_FILE "virus.log"
   ```

4. **CustomStringReplace Function**: Ini adalah fungsi untuk menggantikan semua kemunculan string khusus (dalam hal ini, "3ncrYp73DStr1nG") dalam sebuah string dengan string pengganti (dalam hal ini, "[ENCRYPTED_STRING]").
   ```c
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

   ```

6. **CustomLog Function**: Fungsi ini digunakan untuk mencatat waktu dan file yang terpengaruh saat menggantikan string khusus.
   ```c
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
   ```

8. **ScanAndReplace Function**: Fungsi ini melakukan pemindaian rekursif pada direktori yang diberikan dan mengganti string khusus dalam semua file di dalamnya menggunakan fungsi `CustomStringReplace`. Jika sebuah direktori ditemukan, fungsi akan memanggil dirinya sendiri secara rekursif untuk memindai subdirektori.
   ```c
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
   ```

10. **Main Function**: Program dimulai dengan memeriksa apakah argumen yang diberikan sesuai (hanya satu path folder yang diperlukan). Kemudian, program berjalan sebagai daemon yang berulang kali memanggil `ScanAndReplace` pada folder yang ditentukan setiap 15 detik.
    ```c
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
    ```

### Cara Kerja

- Program akan dijalankan dengan memberikan path folder sebagai argumen.
- Virus akan terus memindai folder dan subfolder secara rekursif setiap 15 detik.
- Setiap kali ia menemukan file yang mengandung string "3ncrYp73DStr1nG", string tersebut akan diganti dengan "[ENCRYPTED_STRING]" dalam file tersebut.
- Setiap perubahan yang dilakukan akan dicatat dalam file log `virus.log` beserta waktu dan nama file yang terpengaruh.

### Virus.c Output


![Screenshot 2024-04-26 172950](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/150202762/2551e1d4-2dba-4683-8d7b-8ed72c0b7cf7)


![Screenshot 2024-04-26 173058](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/150202762/1e2cc192-98ef-485d-93cd-a4efb9f2ad53)


## Soal 2

Paul adalah seorang mahasiswa semester 4 yang diterima magang di perusahaan XYZ. Pada hari pertama magang, ia diberi tugas oleh atasannya untuk membuat program manajemen file sederhana. Karena kurang terbiasa dengan bahasa C dan environment Linux, ia meminta bantuan kalian untuk mengembangkan program tersebut.

a. Atasannya meminta agar program tersebut dapat berjalan secara daemon dan dapat mengunduh serta melakukan unzip terhadap file berikut. Atasannya juga meminta program ini dibuat tanpa menggunakan command system()

b. Setelah ditelusuri, ternyata hanya 6 file teratas yang nama filenya tidak dienkripsi. Oleh karena itu, bantulah Paul untuk melakukan dekripsi terhadap nama file ke-7 hingga terakhir menggunakan algoritma ROT19

c. Setelah dekripsi selesai, akan terlihat bahwa setiap file memuat salah satu dari kode berikut: r3N4mE, d3Let3, dan m0V3. Untuk setiap file dengan nama yang memuat kode d3Let3, hapus file tersebut. Sementara itu, untuk setiap file dengan nama yang memuat kode r3N4mE, lakukan hal berikut:

- Jika ekstensi file adalah “.ts”, rename filenya menjadi “helper.ts”
- Jika ekstensi file adalah “.py”, rename filenya menjadi “calculator.py”
- Jika ekstensi file adalah “.go”, rename filenya menjadi “server.go”
- Jika file tidak memuat salah satu dari ekstensi diatas, rename filenya menjadi “renamed.file”

d. Atasan Paul juga meminta agar program ini dapat membackup dan merestore file. Oleh karena itu, bantulah Paul untuk membuat program ini menjadi 3 mode, yaitu:
*default*: program berjalan seperti biasa untuk me-rename dan menghapus file. Mode ini dieksekusi ketika program dijalankan tanpa argumen tambahan, yaitu dengan command ./management saja

*backup*: program memindahkan file dengan kode m0V3 ke sebuah folder bernama “backup”

*restore*: program mengembalikan file dengan kode m0V3 ke folder sebelum file tersebut dipindahkan

Contoh penggunaan: ./management -m backup

e. Terkadang, Paul perlu mengganti mode dari program ini tanpa menghentikannya terlebih dahulu. Oleh karena itu, bantulan Paul untuk mengintegrasikan kemampuan untuk mengganti mode ini dengan mengirim sinyal ke daemon, dengan ketentuan:

__SIGRTMIN__ untuk mode default

__SIGUSR1__ untuk mode backup

__SIGUSR2__ untuk mode restore

Contoh penggunaan: kill -SIGUSR2 <pid_program>

f. Program yang telah dibuat ini tidak mungkin akan dijalankan secara terus-menerus karena akan membebani sistem. Maka dari itu, bantulah Paul untuk membuat program ini dapat dimatikan dengan aman dan efisien

g. Terakhir, program ini harus berjalan setiap detik dan mampu mencatat setiap peristiwa yang terjadi ke dalam file .log yang bernama “history.log” dengan ketentuan:

Format: [nama_user][HH:MM:SS] - <nama_file> - <action>
nama_user adalah username yang melakukan action terhadap file
Format action untuk setiap kode:
kode r3N4mE: Successfully renamed.
kode d3Let3: Successfully deleted.
mode backup: Successfully moved to backup.
mode restore: Successfully restored from backup.
Contoh pesan log:
[paul][00:00:00] - r3N4mE.ts - Successfully renamed.
[paul][00:00:00] - m0V3.xk1 - Successfully restored from backup.

Berikut adalah struktur folder untuk pengerjaan nomor 2:
    soal_2/
    
    ├── history.log
    ├── management.c
    └── library/
        └── backup/
### Penjelasan Soal Management.c 
1. **Memasukkan library yang dibutuhkan** : Langkah Pertama dari mengerjakan soal ini adalah memasukkan library yang akan kita butuhkan, untuk itu kita harus memasukkan library - library yang diantaranya adalah `<stdio.h>`, `<stdlib.h>`, `<time.h>`, dan lain lain.
2. **Define maksimal buffer size** : Mendefinisikan atau memberi batas maksimal tersebut
   ```
   #define MAX_BUFFER_SIZE 1024
   ```
3. **Declare Char** : Declare beberapa char yang dibutuhkan diawal namun nantinya masih dibutuhkan declare char disetiap fungsi terutama untuk penggunaan fungsi rekursif dan pointer
    ```
    char cwd[MAX_BUFFER_SIZE];
    char dir_path[MAX_BUFFER_SIZE];
    char log_file_path[MAX_BUFFER_SIZE];
    ```
4. **Declare Variabel Khusus** : Disini diperlukan deklarasi variabel khusus dengan beberapa fungsi yaitu `volatile` yang berfungsi untuk memberitahu compiler bahwa nilai variabel bisa berubah kapan saja,  `<sig_atomic_t>` ini adalah tipe data yang digunakan untuk variabel yang bisa diakses sebagai satu unit atomik dari sebuah handler sinyal, lalu `<mode = 0>` ini adalah inisialisasi variabel mode dengan nilai 0. Ini mengatur nilai awal dari variabel tersebut, dan nilai ini bisa diubah oleh program, misalnya dalam respons terhadap sinyal tertentu atau peristiwa lain.
 ```
 volatile sig_atomic_t mode = 0;
 ```
5. **Declare Beberapa fungsi untuk handling signal** : Disini kita memerlukan beberapa fungsi untuk dideklarasikan terlebih dahulu yang mana digunakan untuk melaksanakan mode sesuai signal yang diberikan sesuai pada soal poin e.
 ```
void handle_default(int signal_number) { mode = 0; }
void handle_backup(int signal_number) { mode = 1; }
void handle_restore(int signal_number) { mode = 2; }
void handle_exit(int signal_number) { exit(EXIT_SUCCESS); }
 ```
6. **Membuat Fungsi Default** : Didalam mode default ini akan ada beberapa fungsi yang kita gunakan diantaranya `download_file`, `unzip_file`, `rename_file`, dan lain lain
```
void default_mode()
{
   void remove_directory_and_zip(const char *dir_path) {
    // Menggabungkan path direktori dengan nama folder dan zip
    char folder_path[MAX_BUFFER_SIZE];
    snprintf(folder_path, sizeof(folder_path), "%s/library", dir_path);

    char zip_path[MAX_BUFFER_SIZE];
    snprintf(zip_path, sizeof(zip_path), "%s/library.zip", dir_path);

    //  Membuat proses baru untuk menghapus folder perpustakaan
    pid_t pid = fork();

    if (pid < 0) {
        perror("Gagal membuat fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Proses anak untuk menghapus folder perpustakaan
        char *cmd = "/bin/rm";
        char *argv[] = {"rm", "-rf", folder_path, NULL};
        execv(cmd, argv);
        perror("Gagal mengeksekusi fungsi rm");
        exit(EXIT_FAILURE);
    } else {
        // Proses induk menunggu sampai proses anak selesai
        int status;
        wait(&status);

        // Membuat fork lagi untuk menghapus file zip
        pid = fork();

        if (pid < 0) {
            perror("Gagal membuat fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // Proses anak untuk menghapus file zip
            char *cmd = "/bin/rm";
            char *argv[] = {"rm", zip_path, NULL};
            execv(cmd, argv);
            perror("Gagal mengeksekusi fungsi rm");
            exit(EXIT_FAILURE);
        } else {
            // Proses induk menunggu sampai proses anak kedua selesai
            wait(&status);
        }
    }
}

    void download_file() {
    // Membuat proses baru
    pid_t pid = fork(); 

     // Aman memasukkan path
    char download_path[MAX_BUFFER_SIZE];
    snprintf(download_path, sizeof(download_path), "%s", dir_path); 

    if (pid < 0) {
        perror("Gagal membuat fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Proses anak untuk mendownload file
        char *cmd = "/bin/wget";
        char *argv[] = {
            "wget", "--content-disposition", "--no-check-certificate",
            "https://drive.google.com/uc?export=download&id=1rUIZmp10lXLtCIH3LAZJzRPeRks3Crup",
            "-P", download_path, NULL
        };
        execv(cmd, argv);
        perror("Gagal menjalankan wget");
        exit(EXIT_FAILURE);
    } else {
        // Proses induk menunggu sampai proses anak selesai
        int status;
        wait(&status);
    }
}
    void unzip_file() {
    // Membuat proses baru
    pid_t pid = fork(); 

    // Aman menggabungkan string
    char unzip_path[MAX_BUFFER_SIZE];
    snprintf(unzip_path, sizeof(unzip_path), "%s/library.zip", dir_path); 

    if (pid < 0) {
        perror("Gagal membuat fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Proses anak untuk mengekstrak file zip
        char *cmd = "/bin/unzip";
        char *argv[] = {"unzip", unzip_path, "-d", dir_path, NULL};
        execv(cmd, argv);
        perror("Gagal menjalankan unzip");
        exit(EXIT_FAILURE);
    } else {
        // Proses induk menunggu sampai proses anak selesai
        int status;
        wait(&status);
    }
}
char rot19(char c) {
    if (isalpha(c)) {
        char base = islower(c) ? 'a' : 'A';
        return (c - base + 19) % 26 + base;  // Mengimplementasikan ROT19
    }
    return c;
}

   // Fungsi rot19 dianggap sudah didefinisikan di tempat lain dalam file yang sama
char rot19(char c);

void decrypt_filename() {
    char path[MAX_BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/library/", dir_path);  // Aman membangun path

    DIR *dir = opendir(path);
    if (!dir) {
        perror("Gagal membuka direktori");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *filename = entry->d_name;
        char new_filename[MAX_BUFFER_SIZE];

        // Lewatkan file yang nama awalnya angka atau titik
        if (isdigit(filename[0]) || filename[0] == '.') continue;

        // Enkripsi nama file
        int len = strlen(filename);
        for (int i = 0; i < len; i++) {
            new_filename[i] = rot19(filename[i]);
        }
        new_filename[len] = '\0';  // Menambahkan null terminator

        // Membangun path lengkap untuk nama lama dan baru
        char old_path[MAX_BUFFER_SIZE], new_path[MAX_BUFFER_SIZE];
        snprintf(old_path, sizeof(old_path), "%s%s", path, filename);
        snprintf(new_path, sizeof(new_path), "%s%s", path, new_filename);

        // Membuat proses baru untuk mengganti nama file
        pid_t pid = fork();

        if (pid < 0) {
            perror("Gagal membuat fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            char *cmd = "/bin/mv";
            char *argv[] = { "mv", old_path, new_path, NULL };
            execv(cmd, argv);
            perror("Gagal menjalankan mv");
            exit(EXIT_FAILURE);
        } else {
            int status;
            wait(&status);
        }
    }
    closedir(dir);
}
   void rename_file() {
    char path[MAX_BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/library/", dir_path);

    DIR *dir = opendir(path);
    if (!dir) {
        perror("Gagal membuka direktori");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *filename = entry->d_name;

        if (strstr(filename, "r3N4mE") == NULL || filename[0] == '.') continue;

        FILE *file = fopen(log_file_path, "a");
        if (file != NULL) {
            fprintf(file, "[%s][%02d:%02d:%02d] - %s - Successfully renamed.\n",
                    username, digitime->tm_hour, digitime->tm_min, digitime->tm_sec, filename);
            fclose(file);
        }

        char old_path[MAX_BUFFER_SIZE], new_path[MAX_BUFFER_SIZE];
        snprintf(old_path, sizeof(old_path), "%s%s", path, filename);

        const char *new_filename = "renamed.file"; // Default new filename
        if (strstr(filename, ".ts") != NULL) {
            new_filename = "helper.ts";
        } else if (strstr(filename, ".py") != NULL) {
            new_filename = "calculator.py";
        } else if (strstr(filename, ".go") != NULL) {
            new_filename = "server.go";
        }
        snprintf(new_path, sizeof(new_path), "%s%s", path, new_filename);

        pid_t pid = fork();

        if (pid < 0) {
            perror("Gagal membuat fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            char *cmd = "/bin/mv";
            char *argv[] = {"mv", old_path, new_path, NULL};
            execv(cmd, argv);
            perror("Gagal menjalankan mv");
            exit(EXIT_FAILURE);
        } else {
            int status;
            wait(&status);
        }
    }
    closedir(dir);
}
   void delete_file() {
    char path[MAX_BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/library/", dir_path);

    DIR *dir = opendir(path);
    if (!dir) {
        perror("Gagal membuka direktori");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *filename = entry->d_name;

        if (strstr(filename, "d3Let3") == NULL || filename[0] == '.') continue;

        FILE *file = fopen(log_file_path, "a");
        if (file != NULL) {
            // Misalkan kita memperoleh waktu sekarang untuk log
            time_t now = time(NULL);
            digitime = localtime(&now);

            fprintf(file, "[%s][%02d:%02d:%02d] - %s - Successfully deleted.\n",
                    username, digitime->tm_hour, digitime->tm_min, digitime->tm_sec, filename);
            fclose(file);
        }

        char file_path[MAX_BUFFER_SIZE];
        snprintf(file_path, sizeof(file_path), "%s%s", path, filename);

        pid_t pid = fork();

        if (pid < 0) {
            perror("Gagal membuat fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            char *cmd = "/bin/rm";
            char *argv[] = {"rm", file_path, NULL};
            execv(cmd, argv);
            perror("Gagal menjalankan rm");
            exit(EXIT_FAILURE);
        } else {
            int status;
            wait(&status);
        }
    }
    closedir(dir);
}
}
```
7. **Membuat Fungsi Backup** : Fungsi Backup juga harus dibuat untuk memenuhi permintaan soal
```
void backup() {
    char path[MAX_BUFFER_SIZE], backup_path[MAX_BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/library/", dir_path);
    snprintf(backup_path, sizeof(backup_path), "%sbackup/", path);

    DIR *dir = opendir(path);
    if (!dir) {
        perror("Gagal membuka direktori");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("Gagal membuat fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        struct stat st;
        if (stat(backup_path, &st) != 0) {  // Hanya buat direktori jika belum ada
            char *cmd = "/bin/mkdir";
            char *argv[] = { "mkdir", backup_path, NULL };
            execv(cmd, argv);
            perror("Gagal menjalankan mkdir");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    } else {
        int status;
        wait(&status);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *filename = entry->d_name;

        if (strstr(filename, "m0V3") == NULL || filename[0] == '.') continue;

        FILE *file = fopen(log_file_path, "a"); 
        if (file != NULL) {
            time_t now = time(NULL);
            digitime = localtime(&now);
            fprintf(file, "[%s][%02d:%02d:%02d] - %s - Successfully moved to backup.\n",
                    username, digitime->tm_hour, digitime->tm_min, digitime->tm_sec, filename); 
            fclose(file);
        }

        char file_path[MAX_BUFFER_SIZE], file_backup_path[MAX_BUFFER_SIZE];
        snprintf(file_path, sizeof(file_path), "%s%s", path, filename);
        snprintf(file_backup_path, sizeof(file_backup_path), "%s%s", backup_path, filename);

        pid = fork();

        if (pid < 0) {
            perror("Gagal membuat fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            char *cmd = "/bin/mv";
            char *argv[] = { "mv", file_path, file_backup_path, NULL };
            execv(cmd, argv);
            perror("Gagal menjalankan mv");
            exit(EXIT_FAILURE);
        } else {
            int status;
            wait(&status);
        }
    }
    closedir(dir);
}
```
8. **Membuat Fungsi Restore** : Membuat fungsi yang dapat menjalankan mode restore seperti pada soal
```
void restore() {
    char path[MAX_BUFFER_SIZE], backup_path[MAX_BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/library/", dir_path);
    snprintf(backup_path, sizeof(backup_path), "%sbackup/", path);

    DIR *dir = opendir(backup_path);
    if (!dir) {
        perror("Gagal membuka direktori backup");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *filename = entry->d_name;

        if (strstr(filename, "m0V3") == NULL || filename[0] == '.') continue;

        FILE *file = fopen(log_file_path, "a");
        if (file != NULL) {
            time_t now = time(NULL);
            digitime = localtime(&now);
            fprintf(file, "[%s][%02d:%02d:%02d] - %s - Successfully restored from backup.\n",
                    username, digitime->tm_hour, digitime->tm_min, digitime->tm_sec, filename);
            fclose(file);
        }

        char file_path[MAX_BUFFER_SIZE], file_backup_path[MAX_BUFFER_SIZE];
        snprintf(file_path, sizeof(file_path), "%s%s", path, filename);
        snprintf(file_backup_path, sizeof(file_backup_path), "%s%s", backup_path, filename);

        pid_t pid = fork();

        if (pid < 0) {
            perror("Gagal membuat fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            char *cmd = "/bin/mv";
            char *argv[] = { "mv", file_backup_path, file_path, NULL };
            execv(cmd, argv);
            perror("Gagal menjalankan mv");
            exit(EXIT_FAILURE);
        } else {
            int status;
            wait(&status);
        }
    }
    closedir(dir);
}
```
9. **Deklarasi Variabel Global** : Kita bisa mengetahui dari fungsi fungsi diatas ada beberapa variabel yang mungkin sudah seharusnya dideklarasikan namun karena penggunaannya berulang kali, maka variabel ini dideklarasikan sebelum fungsi main sehingga menandakan bahwa variabel ini merupakan variabel global dan bisa diinisiasi oleh fungsi manapun dalam kode.
```
char *username;
time_t runtime;
struct tm *digitime;
```
10. **Fungsi Main dari kode** : Setelah kita sudah membuat fungsi - fungsi yang dibutuhkan, dibagian akhir kita perlu fungsi utama yang dibutuhkan program yang bisa berisi loop dan berbagai kebutuhan untuk mengeksekusi program.
```
int main(int argc, char **argv)
{
    char cwd[MAX_BUFFER_SIZE];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("Gagal mendapatkan direktori kerja saat ini");
        exit(EXIT_FAILURE);
    }

    // Membangun path direktori dan log file
    snprintf(dir_path, sizeof(dir_path), "%s", cwd);
    snprintf(log_file_path, sizeof(log_file_path), "%s/history.log", dir_path);

    // Mendapatkan username pengguna saat ini
    username = getlogin();
    if (username == NULL) {
        perror("Gagal mendapatkan nama pengguna");
        username = "unknown";  // Username alternatif jika gagal
    }

    // Mendapatkan waktu saat ini
    runtime = time(NULL);
    digitime = localtime(&runtime);

    // Menyetel penanganan sinyal
    signal(SIGRTMIN, handle_default);
    signal(SIGUSR1, handle_backup);
    signal(SIGUSR2, handle_restore);
    signal(SIGTERM, handle_exit);

    // Mengecek argumen baris perintah
    if (argc == 3 && strcmp(argv[1], "-m") == 0) {
        if (strcmp(argv[2], "backup") == 0) mode = 1;
        else if (strcmp(argv[2], "restore") == 0) mode = 2;
    }

    pid_t pid, sid;

    pid = fork();

    if (pid < 0) {
        perror("Proses fork gagal");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    // Membuat sesi baru dan mengubah direktori kerja
    sid = setsid();
    if (sid < 0) {
        perror("setsid gagal");
        exit(EXIT_FAILURE);
    }

    if (chdir("/") < 0) {
        perror("Gagal mengubah direktori ke /");
        exit(EXIT_FAILURE);
    }

    // Menutup file descriptor standar
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Loop utama program
    while (1) {
        switch(mode) {
            case 0:
                handle_default(SIGRTMIN);  // asumsi mode default ditangani di sini
                break;
            case 1:
                backup();
                break;
            case 2:
                restore();
                break;
        }
        sleep(100);
    }

    return 0;  // Baris ini tidak akan pernah tercapai
}
```
### Cara Kerja Management.c 
1. Kompilasi kode menggunakan compiler pada lingkungan linux, pada kasus ini saya menggunakan gcc. Sehingga langkah pertama saya harus menggunakan perintah `gcc management.c -o management`
2. Eksekusi file dengan perintah `./management.c`
3. lalu gunakan perintah `ls` untuk memeriksa apakah berhasil tidak. Jika berhasil akan muncul direktori `library` yang mana jika kita masuk kedalamnya dengan perintah `cd library` maka kita akan masuk dan dapat melihat file yang telah di unzip
4. lalu jika sudah memastikan fungsi tersebut, kita harus memeriksa apakah fungsi backup bisa yaitu dengan perintah `./management -m backup`, jika berhasil maka ketika masuk ke library kita bisa melihat backup sebagai direktori yang menyimpan beberapa file selain yang sudah berubah seperti `calculator.py` dan lain lain.
5. lalu kita juga harus memeriksa fungsi lain yaitu restore yang akan menggunakan perintah sebagai berikut `./management -m restore` perintah ini akan membuat direktori backup kosong dan mengembalikan file ke direktori library
### Revisi
1. Keseluruhan Kode sehingga bisa menjalankan fungsi sebisa mungkin
2. Kode berhasil direvisi sampai bisa melaksanakan download beserta unzip file, fungsi restore dan backup. Untuk fungsi signal masih terkendala
### Output Management.c
![WhatsApp Image 2024-04-27 at 01 08 19 (2)](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/144348985/237a5d98-9305-47b5-9e06-2296daade986)
![WhatsApp Image 2024-04-27 at 01 08 19 (1)](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/144348985/a707d38a-d721-4690-849f-e6791342c437)
![WhatsApp Image 2024-04-27 at 01 08 19](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/144348985/e308183e-9a3e-4ce7-9768-0aa76d534f0a)



## Soal 3
Pak Heze adalah seorang admin yang baik. Beliau ingin membuat sebuah program admin yang dapat memantau para pengguna sistemnya. Bantulah Pak Heze untuk membuat program  tersebut!

a. Namai program tersebut dengan nama admin.c

b. Program tersebut memiliki fitur menampilkan seluruh proses yang dilakukan oleh seorang user dengan menggunakan command:
./admin <user>

c. Program dapat memantau proses apa saja yang dilakukan oleh user. Fitur ini membuat program berjalan secara daemon dan berjalan terus menerus. Untuk menjalankan fitur ini menggunakan command: 
```
./admin -m <user>
```

d. Dan untuk mematikan fitur tersebut menggunakan: 
```
./admin -s <user>
```
e. Program akan mencatat seluruh proses yang dijalankan oleh user di file <user>.log dengan format:

__[dd:mm:yyyy]-[hh:mm:ss]-pid_process-nama_process_GAGAL/JALAN__

f. Program dapat menggagalkan proses yang dijalankan user setiap detik secara terus menerus dengan menjalankan: 
```
./admin -c user
```
sehingga user tidak bisa menjalankan proses yang dia inginkan dengan baik. Fitur ini dapat dimatikan dengan command:
```
./admin -a user
```
g. Ketika proses yang dijalankan user digagalkan, program juga akan melog dan menset log tersebut sebagai __GAGAL__. Dan jika di log menggunakan fitur poin c, log akan ditulis dengan __JALAN__

### Penjelasan admin.c
1. **Include Library** : Program memulai dengan menyertakan beberapa pustaka standar seperti `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<unistd.h>`, `<sys/types.h>`, `<signal.h>`, `<time.h>`, dan `<sys/wait.h>`. Ini memungkinkan program untuk melakukan operasi I/O, manajemen memori, manipulasi string, menerima sinyal, manipulasi waktu, dan mengatur proses.
   
3. **Makro dan Konstanta**: Program mendefinisikan `MAX_COMMAND_LENGTH` sebagai panjang maksimum string untuk perintah yang akan dieksekusi.
   ```
   #define MAX_COMMAND_LENGTH 1024
   ```
   
4. **show_processes** : Fungsi yang digunakan untuk menampilkan proses yang sedang berjalan dengan menggunakan `fork()` untuk membuat proses baru. Dalam child process terdapat perintah untuk mengeksekusi `ps` untuk menampilkan proses pengguna dan menggunakan `wait()` untuk menunggu child process selesai.
   ```
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
  ``

5. **check_process_status** : Fungsi yang digunakan untuk memeriksa status suatu proses berdasarkan PID. Pertama, membuat path ke file status suatu proses dalam `/proc` dan menggunakan `access()` untuk memeriksa apakah file status ada atau tidak.
   ```
    int check_process_status(int pid) {
      char status_file[MAX_COMMAND_LENGTH];
      snprintf(status_file, MAX_COMMAND_LENGTH, "/proc/%d", pid);
      if (access(status_file, F_OK) != -1) {
          return 1; // Proses sedang berjalan
      } else {
          return 0; // Proses tidak berjalan
      }
    }
   ``

6. **monitor_processes** : Fungsi yang digunakan untuk memantau proses yang dijalankan oleh pengguna dengan membuka file log untuk mencatat informasi proses. Kemudian, melakukan loop dengan menggunakan `ps` melalui `popeon()` untuk mendapatkan daftar proses yang dijalankan dan tiap baris dari output `ps` diproses untuk mendapatkan PID, nama proses, dan status proses kemudian informasi proses dicatat ke file log.
   ```
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
   ``

7. **kill_processes** : Fungsi yang digunakan untuk menghentikan semua proses yang dijalankan dan menghentikannya menggunakan `pkill`.
   ```
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
   ``

8. **main function** : Fungsi utama untuk memeriksa baris perintah untuk menentukan operasi yang dijalankan dengan menggunakan `fork()` untuk membuat proses baru dan `wait()` untuk menunggu child process selesai.
   ```
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
   ``

### Cara kerja admin.c
- Pengguna menjalankan program dengan argumen seperti menampilkan proses yang sedang berjalan, memantau proses yang dijalankan dan mencatat log ke file, menghentikan pemantauan proses yang sedang berlangsung, memulai proses secara terus-menerus, dan menghentikan proses secara terus menerus.
- Jika argumen adalah `-l`, program menampilkan proses yang sedang berjalan.
- Jika argumen adalah `-m`, program memantau proses yang dijalankan dan mencatat log ke file.
- Jika argumen adalah `-s`, program menghentikan pemantauan proses yang sedang berlangsung.
- Jika argumen adalah `-c`, program memulai proses secara terus-menerus.
- Jika argumen adalah `-t`, program menghentikan proses secara terus menerus.
    
### Output admin.c
![Screenshot from 2024-04-27 19-27-28](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/150429708/bd6d237e-5c46-4bb7-8b66-95508e79e79e)

Terdapat kesalahan pada ./admin -c pikaa dimana jika saya run laptop saya mati

### Output pikaa.log
![Screenshot from 2024-04-27 19-29-40](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/150429708/c295e7cf-0dd1-4195-a245-b6de569f4b21)


## Soal 4

Salomo memiliki passion yang sangat dalam di bidang sistem operasi. Saat ini, dia ingin mengotomasi kegiatan-kegiatan yang ia lakukan agar dapat bekerja secara efisien. Bantulah Salomo untuk membuat program yang dapat mengotomasi kegiatan dia!

a. Salomo ingin dapat membuka berbagai macam aplikasi dengan banyak jendela aplikasi dalam satu command. Namai file program tersebut setup.c

b. Program dapat membuka berbagai macam aplikasi dan banyak jendela aplikasi sekaligus (bisa membuka 1 atau lebih aplikasi dengan 1 atau lebih window (kecuali aplikasi yang tidak bisa dibuka dengan banyak window seperti discord)) dengan menjalankan: 
./setup -o <app1> <num1> <app2> <num2>.....<appN> <numN>
Contoh penggunaannya adalah sebagai berikut: 
./setup -o firefox 2 wireshark 2

c. Program akan membuka 2 jendela aplikasi firefox dan 2 jendela aplikasi wireshark.

d. Program juga dapat membuka aplikasi dengan menggunakan file konfigurasi dengan menggunakan 
./setup -f file.conf 

Format file konfigurasi dibebaskan, namun pastikan dapat menjalankan fitur dari poin 2.
Contoh isi file.conf:
```
Firefox 2
Wireshark 3
```
e. Ketika menjalankan command contoh, program akan membuka 2 jendela aplikasi firefox dan 3 jendela aplikasi wireshark.

f. Program dapat mematikan semua aplikasi yg dijalankan oleh program tersebut dengan: 
```
./setup -k
```
g. Program juga dapat mematikan aplikasi yang dijalankan sesuai dengan file konfigurasi. 
Contohnya: 
```
./setup -k file.conf 
```
Command ini hanya mematikan aplikasi yang dijalankan dengan 
```
./setup -f file.conf
```

### Setup.c Penjelasan

1. **Include Libraries**: Program memulai dengan menyertakan beberapa pustaka standar seperti `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<unistd.h>`, `<sys/types.h>`, dan `<sys/wait.h>`. Ini memungkinkan program untuk melakukan operasi I/O, manajemen memori, manipulasi string, dan mengatur proses.

2. **Makro dan Konstanta**: Program mendefinisikan beberapa makro dan konstanta seperti `MAX_APPS` untuk batasan maksimum jumlah aplikasi yang dapat diluncurkan, dan `MAX_NAME_LENGTH` untuk panjang maksimum nama aplikasi.
   ```c
   #define MAX_APPS 10
   #define MAX_NAME_LENGTH 50
   ```

4. **launch_apps Function**: Fungsi ini bertugas meluncurkan aplikasi-aplikasi yang diinginkan oleh pengguna. Setiap aplikasi diluncurkan dengan jumlah instance tertentu menggunakan `fork()` dan `execlp()`.
   ```c
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
   ```

6. **load_configuration Function**: Fungsi ini memuat konfigurasi dari file yang diberikan oleh pengguna. Setiap baris dalam file konfigurasi berisi nama aplikasi dan jumlah instance yang akan diluncurkan. Fungsi ini menggunakan `fork()` dan `execlp()` untuk meluncurkan aplikasi sesuai konfigurasi.
   ```c
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
   ```

8. **terminate_all_apps Function**: Fungsi ini digunakan untuk menutup semua aplikasi yang telah diluncurkan. Menggunakan `pkill` untuk menghentikan aplikasi secara paksa dengan nama yang spesifik.
   ```c
   void terminate_all_apps() {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("pkill", "pkill", "firefox", NULL);
        exit(0);
    } else if (pid < 0) {
        printf("Error: Fork failed\n");
    } else {
        wait(NULL);
    }

    pid = fork();
    if (pid == 0) {
        execlp("pkill", "pkill", "wireshark", NULL);
        exit(0);
    } else if (pid < 0) {
        printf("Error: Fork failed\n");
    } else {
        wait(NULL);
    }
    // Add more applications as needed
   ```

10. **terminate_apps_from_config Function**: Fungsi ini menutup aplikasi-aplikasi yang disebutkan dalam file konfigurasi yang diberikan oleh pengguna. Sama seperti `terminate_all_apps`, namun membaca daftar aplikasi dari file konfigurasi.
    ```c
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
            execlp("pkill", "pkill", app, NULL);
            exit(0);
        } else if (pid < 0) {
            printf("Error: Fork failed\n");
        } else {
            wait(NULL);
        }
    }

    fclose(file);
    ```

12. **Main Function**: Fungsi utama dari program. Memeriksa argumen baris perintah untuk menentukan tindakan yang akan diambil. Kemudian, memanggil fungsi-fungsi yang sesuai berdasarkan argumen yang diberikan.
    ```c
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
    ```

### Cara Kerja

- Pengguna menjalankan program dengan argumen seperti meluncurkan aplikasi, memuat konfigurasi, atau menutup aplikasi.
- Jika argumen adalah `-l`, program meluncurkan aplikasi-aplikasi dengan instance yang sesuai.
- Jika argumen adalah `-c`, program memuat konfigurasi dari file yang diberikan.
- Jika argumen adalah `-t`, program menutup aplikasi-aplikasi, baik semua aplikasi atau berdasarkan konfigurasi yang diberikan.

### Setup.c Output

![Screenshot 2024-04-26 173331](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/150202762/2d57357f-8d7f-4c28-9436-1d1b23e64b18)

![Screenshot 2024-04-26 173404](https://github.com/agnesgriselda/Sisop-2-2024-MH-IT10/assets/150202762/6a66f277-6c2f-4ad2-a148-a449bd2bc2f9)

