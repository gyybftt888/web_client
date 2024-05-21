#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <resolv.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SUCCESS 0
#define FAIL -1

#define TRUE 1
#define FALSE 0

#define NUM_ARG 3
#define NUM_PROCESS 5
#define URL_LEN 256
#define PROTOCOL_LEN 10
#define HOST_LEN 100
#define PATH_LEN 100
#define REQUEST_LEN 100
#define BUFFER_SIZE 4096

#define MKDIR_MODE 0777

#define ID 0
#define URL 1
#define STATUS 2
#define PID 3

// possible value of STATUS in table URL
#define UNVISITED 0
#define PROCESSING 1
#define VISITED 2



// \r\n
#define CRLF_LEN 2
#define SSL_PORT 443

#define PROTOCOL_HTTPS "https"
#define PROTOCOL_HTTP "http"

/*
"CREATE TABLE URL("
    "ID INT PRIMARY KEY NOT NULL,"
    "URL TEXT NOT NULL,"
    "STATUS INT NOT NULL,"
    "PID INT);"
*/
sqlite3 *db;
int *num_url;

// open db and create table named URL
int db_init();
// insert (ID, URL, 'UNVISITED', 0) into table URL
int db_insert(char *);
// take original URL and next URL as argument, modify URL to a new one and do insertion
int db_insert_href(char *, char *, char *, char *);
// pop one unvisited URL and update this URL as visited
int db_select_unvisited(char *);
// mark one PROCESSING URL with given pid as UNVISITED
int db_select_processing(pid_t);
// https connect to host and return (SSL *ssl)
SSL *https(char *);
// http connect to host and return (int sockfd)
int http(char *);
// send request to certain URL
int request(SSL *, int, char *, char *, char *);
// receive response
void response(FILE *, SSL *, int, char *, char *, char *);
// pass header in and extract information we need
int header_info(char *, int *, int *, int *);
// connect to other href link
int href(char *, char *, char *, char *);

int main(int argc, char const *argv[]) {
    if (argc != NUM_ARG) {
        return FAIL;
    }

    if (mkdir(argv[2], MKDIR_MODE) == 0) {
        printf("create folder '%s'\n", argv[2]);
    } else {
        perror("mkdir");
    }

    if ((num_url = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap num_url");
    }
    *num_url = 1;

    db_init();
    db_insert(argv[1]);

    pid_t pid[NUM_PROCESS];
    for (int i = 0; i < NUM_PROCESS; i++) {
        pid[i] = fork();
        if (pid[i] < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        } else if (pid[i] == 0) {
            if (i) {
                sleep(5);
            }
            char url[URL_LEN] = {0};
            char protocol[PROTOCOL_LEN] = {0};
            char hostname[HOST_LEN] = {0};
            char path[PATH_LEN] = {0};
            db_select_unvisited(url);
            db_update_pid(url, getpid());
            sscanf(url, "%[^:]://%[^/]%s", protocol, hostname, path);

            char filename[strlen(hostname) + 10];
            snprintf(filename, sizeof(filename), "%s-%d.txt", hostname, *num_url);
            char filepath[strlen(argv[2]) + 1 + strlen(filename) + 1];
            snprintf(filepath, sizeof(filepath), "%s/%s", argv[2], filename);
            FILE *file_w = fopen(filepath, "w");

            SSL *ssl = NULL;
            int sockfd = 0;
            if (!strcmp(protocol, PROTOCOL_HTTPS)) {
                ssl = https(hostname);
                if (!ssl) {
                    continue;
                }
            } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
                sockfd = http(hostname);
                if (!sockfd) {
                    continue;
                }
            }
            if (request(ssl, sockfd, protocol, hostname, path) == FAIL) {
                perror("request");
            }
            response(file_w, ssl, sockfd, protocol, hostname, path);
            db_visited(url);
            if (!strcmp(protocol, PROTOCOL_HTTPS)) {
                SSL_free(ssl);
            } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
                close(sockfd);
            }
            fclose(file_w);
        }
    }

    for (int i = 0; i < NUM_PROCESS; i++) {
        int status;
        pid_t child_pid = waitpid(pid[i], &status, 0);
        if (child_pid == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
        if (WIFEXITED(status)) {
            printf("pid:%d exited with status %d\n", child_pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("pid:%d was terminated by signal %d\n", child_pid, WTERMSIG(status));
            db_update_status(child_pid);
        } else if (WIFSTOPPED(status)) {
            printf("pid:%d was stopped by signal %d\n", child_pid, WSTOPSIG(status));
            db_update_status(child_pid);
        } else {
            printf("pid:%d ended unexpectedly\n", child_pid);
            db_update_status(child_pid);
        }
    }
    return SUCCESS;
}

int db_init() {
    char *zErrMsg = 0;
    int rc = sqlite3_open("url.db", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return rc;
    } else {
        fprintf(stdout, "Opened database successfully\n");
    }
    const char *sql =
        "CREATE TABLE URL("
        "ID INT PRIMARY KEY NOT NULL,"
        "URL TEXT NOT NULL,"
        "STATUS INT NOT NULL,"
        "PID INT);";
    rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Table created successfully\n");
    }
    return rc;
}

int db_insert(char *url) {
    sqlite3_stmt *select_stmt, *insert_stmt;
    const char *select_sql = "SELECT * FROM URL;";
    const char *insert_sql = "INSERT INTO URL (ID, URL, STATUS, PID) VALUES (?, ?, ?, ?);";
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    while (sqlite3_step(select_stmt) == SQLITE_ROW) {
        if (!strcmp(url, sqlite3_column_text(select_stmt, URL))) {
            return rc;
        }
    }
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_bind_int(insert_stmt, 1, *num_url);
    sqlite3_bind_text(insert_stmt, 2, url, -1, SQLITE_STATIC);
    sqlite3_bind_int(insert_stmt, 3, UNVISITED);
    sqlite3_bind_int(insert_stmt, 4, 0);
    rc = sqlite3_step(insert_stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    *num_url += 1;
    sqlite3_finalize(insert_stmt);
    return rc;
}

int db_insert_href(char *protocol, char *hostname, char *path, char *next_url) {
    char url[URL_LEN];
    if (strstr(next_url, "http") != NULL) {
        strncpy(url, next_url, URL_LEN);
    } else if (next_url[0] == '/' && next_url[1] == '/') {
        snprintf(url, URL_LEN, "%s:%s", protocol, next_url);

    } else if (next_url[0] == '/') {
        snprintf(url, URL_LEN, "%s://%s%s", protocol, hostname, next_url);

    } else {
        snprintf(url, URL_LEN, "%s://%s%s%s", protocol, hostname, path, next_url);
    }
    db_insert(url);
    return SUCCESS;
}

int db_select_unvisited(char *url) {
    sqlite3_stmt *select_stmt, *update_stmt;
    const char *select_sql = "SELECT * FROM URL;";
    const char *update_sql = "UPDATE URL set STATUS = ? where URL = ?; ";
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    while (sqlite3_step(select_stmt) == SQLITE_ROW) {
        if (sqlite3_column_int(select_stmt, STATUS) == UNVISITED) {
            rc = sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
                return rc;
            }
            sqlite3_bind_int(update_stmt, 1, PROCESSING);
            sqlite3_bind_text(update_stmt, 2, sqlite3_column_text(select_stmt, 1), -1, SQLITE_STATIC);
            rc = sqlite3_step(update_stmt);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
                return rc;
            }
            strncpy(url, sqlite3_column_text(select_stmt, 1), URL_LEN);
            sqlite3_finalize(update_stmt);
            sqlite3_finalize(select_stmt);
            return rc;
        }
    }
    return rc;
}

int db_update_status(pid_t pid){

}

int db_update_pid(char *url, pid_t pid) {
    sqlite3_stmt *stmt;
    const char *sql = "UPDATE URL set PID = ? where URL = ?; ";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_bind_int(stmt, 1, pid);
    sqlite3_bind_text(stmt, 2, url, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_finalize(stmt);
    return rc;
}

int db_visited(char *url) {
    sqlite3_stmt *stmt;
    const char *sql = "UPDATE URL set STATUS = 2 where URL = ?; ";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_bind_text(stmt, 1, url, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_finalize(stmt);
    return rc;
}

SSL *https(char *hostname) {
    SSL_CTX *ctx;
    int sockfd;
    SSL *ssl;
    SSL_METHOD *method;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);

    }
    struct hostent *host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        return NULL;
    }
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SSL_PORT);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror(hostname);
        return NULL;
    }
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    } else {
        return ssl;
    }
}

int http(char *hostname) {
    struct addrinfo hints, *servinfo, *p;
    int sockfd, info;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((info = getaddrinfo(hostname, PROTOCOL_HTTP, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(info));
        return FAIL;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue;
        }
        if (connect(sockfd, (struct sockaddr *)p->ai_addr, p->ai_addrlen) != 0) {
            perror("connect failed. retrying...");
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if (p == NULL) {
        fprintf(stderr, "failed to bind socket\n");
        return FAIL;
    } else {
        return sockfd;
    }
}

int request(SSL *ssl, int sockfd, char *protocol, char *hostname, char *path) {
    char msg[REQUEST_LEN];
    snprintf(msg, sizeof(msg), "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, hostname);
    if (!strcmp(protocol, PROTOCOL_HTTPS)) {
        if (SSL_write(ssl, msg, strlen(msg)) <= 0) {
            return FAIL;
        }
    } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
        if (send(sockfd, msg, strlen(msg), 0) <= 0) {
            return FAIL;
        }
    }
    return SUCCESS;
}

void response(FILE *file_w, SSL *ssl, int sockfd, char *protocol, char *hostname, char *path) {
    char buffer[BUFFER_SIZE] = {0};
    int recvd;

    if (!strcmp(protocol, PROTOCOL_HTTPS)) {
        recvd = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
        recvd = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    }
    buffer[recvd] = '\0';
    char *header_beg = strstr(buffer, "HTTP/1.1 ");
    char *header_end = strstr(header_beg, "\r\n\r\n");
    char *header = strndup(header_beg, header_end - header_beg);
    int statuscode = 0;
    int is_html = FALSE;
    int chunked = FALSE;
    header_info(header, &statuscode, &is_html, &chunked);
    if (statuscode == 301 || statuscode == 302 || statuscode == 307 || statuscode == 308) {
        char *location_beg = strstr(header, "Location: ") + strlen("Location: ");
        char *location_end = strstr(location_beg, "\n");
        char *next_url = strndup(location_beg, location_end - location_beg);
        db_insert_href(protocol, hostname, path, next_url);
        return;
    }
    free(header);
    if (is_html == FALSE) {
        return;
    }
    char *buf_left_beg = strstr(buffer, "\r\n\r\n") + strlen("\r\n\r\n");
    int buf_left_size = buffer + recvd - buf_left_beg;
    char *buf_left = strndup(buf_left_beg, buf_left_size);

    href(buf_left, protocol, hostname, path);

    if (!chunked) {
        fputs(buf_left, file_w);
        memset(buffer, '\0', sizeof(buffer));
        if (!strcmp(protocol, PROTOCOL_HTTPS)) {
            while ((recvd = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
                buffer[recvd] = '\0';
                fwrite(buffer, sizeof(char), recvd, file_w);
                href(buffer, protocol, hostname, path);
                memset(buffer, '\0', sizeof(buffer));
            }
        } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
            while ((recvd = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
                buffer[recvd] = '\0';
                fwrite(buffer, sizeof(char), recvd, file_w);
                href(buffer, protocol, hostname, path);
                memset(buffer, '\0', sizeof(buffer));
            }
        }
    } else {
        char *chunk_beg = buf_left_beg;
        char *data_beg = strstr(chunk_beg, "\r\n") + CRLF_LEN;

        int size_size = strstr(chunk_beg, "\r\n") - chunk_beg;
        int data_size = strtol(chunk_beg, NULL, 16);

        int chunk_size = size_size + CRLF_LEN + data_size + CRLF_LEN;

        while (buf_left_size >= chunk_size) {
            fwrite(data_beg, sizeof(char), data_size + CRLF_LEN, file_w);
            buf_left_beg += chunk_size;
            buf_left_size -= chunk_size;

            chunk_beg += chunk_size;
            data_beg = strstr(chunk_beg, "\r\n") + CRLF_LEN;

            size_size = strstr(chunk_beg, "\r\n") - chunk_beg;
            data_size = strtol(chunk_beg, NULL, 16);
            if (data_size == 0) {
                return;
            }
            chunk_size = size_size + CRLF_LEN + data_size + CRLF_LEN;
        }
        fwrite(data_beg, sizeof(char), buf_left_size - size_size - CRLF_LEN, file_w);

        // modify data_size -> indicate how much data left
        data_size -= (buf_left_size - size_size - CRLF_LEN);
        memset(buffer, '\0', sizeof(buffer));

        // flag to indicate if chunk processed
        int new_chunk = 0;
        if (!strcmp(protocol, PROTOCOL_HTTPS)) {
            while ((recvd = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
                buffer[recvd] = '\0';
                href(buffer, protocol, hostname, path);
                if (new_chunk) {
                    chunk_beg = buffer;
                    data_beg = strstr(buffer, "\r\n") + CRLF_LEN;

                    size_size = strstr(buffer, "\r\n") - chunk_beg;
                    data_size = strtol(chunk_beg, NULL, 16);
                    if (data_size == 0) {
                        return;
                    }

                    chunk_size = size_size + CRLF_LEN + data_size + CRLF_LEN;
                    buf_left_beg = buffer;
                    buf_left_size = recvd;

                    while (buf_left_size >= chunk_size) {
                        fwrite(data_beg, sizeof(char), data_size + CRLF_LEN, file_w);
                        buf_left_beg += chunk_size;
                        buf_left_size -= chunk_size;

                        chunk_beg += chunk_size;
                        data_beg = strstr(chunk_beg, "\r\n") + CRLF_LEN;

                        size_size = strstr(chunk_beg, "\r\n") - chunk_beg;
                        data_size = strtol(chunk_beg, NULL, 16);
                        if (data_size == 0) {
                            return;
                        }
                        chunk_size = size_size + CRLF_LEN + data_size + CRLF_LEN;
                    }
                    fwrite(data_beg, sizeof(char), buf_left_size - size_size - CRLF_LEN, file_w);
                    data_size -= (buf_left_size - size_size - CRLF_LEN);
                    memset(buffer, '\0', sizeof(buffer));

                    new_chunk = 0;
                    continue;
                }

                if (data_size > recvd) {
                    fwrite(buffer, sizeof(char), recvd, file_w);
                    data_size -= recvd;
                } else if (data_size + CRLF_LEN == recvd) {
                    fwrite(buffer, sizeof(char), recvd, file_w);
                    data_size = 0;
                    new_chunk = 1;
                } else {
                    fwrite(buffer, sizeof(char), data_size + CRLF_LEN, file_w);
                    buf_left_beg = buffer + data_size + CRLF_LEN;
                    buf_left_size = recvd - (data_size + CRLF_LEN);

                    chunk_beg = buf_left_beg;

                    data_beg = strstr(chunk_beg, "\r\n") + CRLF_LEN;

                    size_size = strstr(chunk_beg, "\r\n") - chunk_beg;
                    data_size = strtol(chunk_beg, NULL, 16);

                    if (data_size == 0) {
                        return;
                    }
                    chunk_size = size_size + CRLF_LEN + data_size + CRLF_LEN;

                    while (buf_left_size >= chunk_size) {
                        fwrite(data_beg, sizeof(char), data_size + CRLF_LEN, file_w);
                        buf_left_beg += chunk_size;
                        buf_left_size -= chunk_size;

                        chunk_beg += chunk_size;
                        data_beg = strstr(chunk_beg, "\r\n") + CRLF_LEN;

                        size_size = strstr(chunk_beg, "\r\n") - chunk_beg;
                        data_size = strtol(chunk_beg, NULL, 16);
                        if (data_size == 0) {
                            return;
                        }
                        chunk_size = size_size + CRLF_LEN + data_size + CRLF_LEN;
                    }
                    fwrite(data_beg, sizeof(char), buf_left_size - size_size - CRLF_LEN, file_w);
                    data_size -= (buf_left_size - size_size - CRLF_LEN);
                }
                memset(buffer, '\0', sizeof(buffer));
            }
        } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
            while ((recvd = recv(sockfd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            }
        }
    }
}

int header_info(char *header, int *statuscode, int *is_html, int *chunked) {
    char *code_beg = strstr(header, "HTTP/1.1 ") + strlen("HTTP/1.1 ");
    char temp[5];
    *statuscode = atoi(strncpy(temp, code_beg, 3));
    if (strstr(header, "\r\nContent-Type: text/html") != NULL) {
        *is_html = TRUE;
    }
    if (strstr(header, "\r\ncontent-type: text/html") != NULL) {
        *is_html = TRUE;
    }
    if (strstr(header, "\r\nTransfer-Encoding: chunked") != NULL) {
        *chunked = TRUE;
    }
    if (strstr(header, "\r\ntransfer-encoding: chunked") != NULL) {
        *chunked = TRUE;
    }
    return SUCCESS;
}

int href(char *buffer, char *protocol, char *hostname, char *path) {
    char *buf_left = buffer;
    while (strstr(buf_left, "href=") != NULL) {
        char *href_beg = strstr(buf_left, "href=") + strlen("href=");
        char *href_end = NULL;
        if (href_beg[0] == '\"') {
            href_beg += 1;
            href_end = strstr(href_beg, "\"");
        } else if (href_beg[0] == '\'') {
            href_beg += 1;
            href_end = strstr(href_beg, "\'");
        } else {
            href_end = strpbrk(href_beg, " >");
        }
        if (!href_end) {
            break;
        }
        char *next_url = strndup(href_beg, href_end - href_beg);
        db_insert_href(protocol, hostname, path, next_url);
        free(next_url);
        buf_left = href_end + 1;
    }
    return SUCCESS;
}