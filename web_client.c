#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <resolv.h>
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

#define GETADDRINFO_ERR 1
#define BIND_SOCKET_FAIL 2
#define SEND_ERR 3

#define MKDIR_MODE 0777

#define NUM_ARGUMENT 3
#define NUM_PROCESS 5
#define Q_SIZE 100
#define FOLDER_SIZE 20
#define URL_LEN 256
#define PROTOCOL_LEN 10
#define HOST_LEN 100
#define PATH_LEN 100
#define REQUEST_LEN 100
#define BUFFER_SIZE 4096

#define Q_MULTIPLIER 10

// \r\n
#define CRLF_LEN 2
#define SSL_PORT 443

#define PROTOCOL_HTTPS "https"
#define PROTOCOL_HTTP "http"

typedef struct process_manager {
    pid_t pid;
    char url[URL_LEN];
} PM;
PM *pm;
// for(int i = front;  i <= rear; i++)
// global variables in shared memory
char (*url_q)[URL_LEN];
char (*visited_q)[URL_LEN];
int *front, *rear, *visited_idx;
pthread_mutex_t *mutex;

// mapping space for shared memory
int mem_map();
// unmapping shared memory
int mem_un_map();
// check if url_q is full
int is_full();
// check if url_q is empty
int is_empty();
// push URL into queue
int enqueue(const char *);
// pop and return URL
char *dequeue();
// check if URL is in visited_q or url_q
int is_visited(const char *);
//  mark URL as visited
int visit(const char *);
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
// take original URL and next URL as argument, modify URL to a new one
int db_insert_href(char *, char *, char *, char *);
// connect to other href link
int href(char *, char *, char *, char *);

int main(int argc, char const *argv[]) {
    if (argc != NUM_ARGUMENT) return FAIL;

    char folder[FOLDER_SIZE];
    strncpy(folder, argv[2], FOLDER_SIZE);
    folder[strcspn(folder, "\n")] = '\0';
    // mkdir() returns succeed ? 0 : -1
    if (mkdir(folder, MKDIR_MODE) == 0) {
        printf("create folder '%s'\n", folder);
    } else {
        perror("mkdir");
    }

    if (mem_map() == (int)MAP_FAILED) {
        perror("mem_map");
        return (int)MAP_FAILED;
    }

    if (enqueue(argv[1]) == FAIL) {
        return FAIL;
    }

    pid_t pid[NUM_PROCESS];
    for (int i = 0; i < NUM_PROCESS; i++) {
        pid[i] = fork();
        if (pid[i] < 0) {
            perror("'fork'");
            exit(EXIT_FAILURE);
        } else if (pid[i] == 0) {
            if (i) {
                sleep(5);
            }
            pm[i].pid = getpid();
            while (!is_empty()) {
                char url[URL_LEN] = {0};
                char protocol[PROTOCOL_LEN] = {0};
                char hostname[HOST_LEN] = {0};
                char path[PATH_LEN] = {0};

                strncpy(url, dequeue(), URL_LEN);

                strncpy(pm[i].url, url, URL_LEN);

                printf("pid:%d  %s\n", getpid(), url);

                if (visit(url) == FAIL) {
                    return FAIL;
                }

                sscanf(url, "%[^:]://%[^/]%s", protocol, hostname, path);

                char filename[strlen(hostname) + 10];
                snprintf(filename, sizeof(filename), "%s-%d.txt", hostname, *visited_idx);
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
                    perror("'request'");
                }
                response(file_w, ssl, sockfd, protocol, hostname, path);

                if (!strcmp(protocol, PROTOCOL_HTTPS)) {
                    SSL_free(ssl);
                } else if (!strcmp(protocol, PROTOCOL_HTTP)) {
                    close(sockfd);
                }
                fclose(file_w);
            }
            exit(EXIT_SUCCESS);
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
            for (int i = 0; i < NUM_PROCESS; i++) {
                if (pm[i].pid == child_pid) {
                    enqueue(pm[i].url);
                }
            }
        } else if (WIFSTOPPED(status)) {
            printf("pid:%d was stopped by signal %d\n", child_pid, WSTOPSIG(status));
            for (int i = 0; i < NUM_PROCESS; i++) {
                if (pm[i].pid == child_pid) {
                    enqueue(pm[i].url);
                }
            }
        } else {
            printf("pid:%d ended unexpectedly\n", child_pid);
            for (int i = 0; i < NUM_PROCESS; i++) {
                if (pm[i].pid == child_pid) {
                    enqueue(pm[i].url);
                }
            }
        }
    }

    if (mem_un_map() == FAIL) {
        return FAIL;
    }
    return SUCCESS;
}

// mmap() returns succeed ? the address at which the mapping was placed : MAP_FAILED
int mem_map() {
    if ((pm = mmap(NULL, NUM_PROCESS * sizeof(PM), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap pm");
        return (int)MAP_FAILED;
    }
    if ((url_q = mmap(NULL, Q_SIZE * URL_LEN * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap url_q");
        munmap(pm, NUM_PROCESS * sizeof(PM));
        return (int)MAP_FAILED;
    }
    if ((visited_q = mmap(NULL, Q_MULTIPLIER * Q_SIZE * URL_LEN * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap visited_q");
        munmap(pm, NUM_PROCESS * sizeof(PM));
        munmap(url_q, Q_SIZE * URL_LEN * sizeof(char));
        return (int)MAP_FAILED;
    }
    if ((front = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap front");
        munmap(pm, NUM_PROCESS * sizeof(PM));
        munmap(url_q, Q_SIZE * URL_LEN * sizeof(char));
        munmap(visited_q, Q_MULTIPLIER * Q_SIZE * URL_LEN * sizeof(char));
        return (int)MAP_FAILED;
    }
    if ((rear = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap rear");
        munmap(pm, NUM_PROCESS * sizeof(PM));
        munmap(url_q, Q_SIZE * URL_LEN * sizeof(char));
        munmap(visited_q, Q_MULTIPLIER * Q_SIZE * URL_LEN * sizeof(char));
        munmap(front, sizeof(int));
        return (int)MAP_FAILED;
    }
    if ((visited_idx = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap visited_idx");
        munmap(pm, NUM_PROCESS * sizeof(PM));
        munmap(url_q, Q_SIZE * URL_LEN * sizeof(char));
        munmap(visited_q, Q_MULTIPLIER * Q_SIZE * URL_LEN * sizeof(char));
        munmap(front, sizeof(int));
        munmap(rear, sizeof(int));
        return (int)MAP_FAILED;
    }
    if ((mutex = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap mutex");
        munmap(pm, NUM_PROCESS * sizeof(PM));
        munmap(url_q, Q_SIZE * URL_LEN * sizeof(char));
        munmap(visited_q, Q_MULTIPLIER * Q_SIZE * URL_LEN * sizeof(char));
        munmap(front, sizeof(int));
        munmap(rear, sizeof(int));
        munmap(visited_idx, sizeof(int));
        return (int)MAP_FAILED;
    }
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(mutex, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);
    *front = *rear = -1;
    *visited_idx = 0;
    return SUCCESS;
}

// munmap() returns succeed ? 0 : -1
int mem_un_map() {
    if (pm) {
        if (munmap(pm, NUM_PROCESS * sizeof(PM)) == -1) {
            return FAIL;
        }
    }
    if (url_q) {
        if (munmap(url_q, Q_SIZE * URL_LEN * sizeof(char)) == -1) {
            return FAIL;
        }
    }
    if (visited_q) {
        if (munmap(visited_q, Q_MULTIPLIER * Q_SIZE * URL_LEN * sizeof(char)) == -1) {
            return FAIL;
        }
    }
    if (front) {
        if (munmap(front, sizeof(int)) == -1) {
            return FAIL;
        }
    }
    if (rear) {
        if (munmap(rear, sizeof(int)) == -1) {
            return FAIL;
        }
    }
    if (visited_idx) {
        if (munmap(visited_idx, sizeof(int)) == -1) {
            return FAIL;
        }
    }
    if (mutex) {
        if (pthread_mutex_destroy(mutex) == 0) {
            if (munmap(mutex, sizeof(pthread_mutex_t)) == -1) {
                return FAIL;
            }
        }
    }
    return SUCCESS;
}

int is_full() { return ((*front == *rear + 1) || (*front == 0 && *rear == Q_SIZE - 1)); }

int is_empty() { return (*front == -1); }

int enqueue(const char *url) {
    pthread_mutex_lock(mutex);

    if (is_full()) {
        printf("Queue Is Full\n");
        pthread_mutex_unlock(mutex);
        return FAIL;
    } else {
        if (*front == -1) *front = 0;
        *rear = (*rear + 1) % Q_SIZE;
        strncpy(url_q[*rear], url, URL_LEN);
        pthread_mutex_unlock(mutex);
        return SUCCESS;
    }
}

char *dequeue() {
    pthread_mutex_lock(mutex);

    if (is_empty()) {
        printf("Queue Is Empty\n");
        pthread_mutex_unlock(mutex);
        return NULL;
    } else {
        int tmp = *front;
        if (*front == *rear) {
            *front = -1;
            *rear = -1;
        } else {
            *front = (*front + 1) % Q_SIZE;
        }
        pthread_mutex_unlock(mutex);
        return url_q[tmp];
    }
}

int is_visited(const char *url) {
    for (int i = 0; i < *visited_idx; i++) {
        if (!strcmp(visited_q[i], url)) {
            return TRUE;
        }
    }
    for (int i = *front; i <= *rear; i++) {
        if (!strcmp(url_q[i], url)) {
            return TRUE;
        }
    }
    return FALSE;
}

int visit(const char *url) {
    pthread_mutex_lock(mutex);

    strncpy(visited_q[*visited_idx], url, URL_LEN);
    (*visited_idx)++;
    if (*visited_idx >= Q_MULTIPLIER * Q_SIZE) {
        printf("Visited Queue Is Full");
        pthread_mutex_unlock(mutex);
        return FAIL;
    } else {
        pthread_mutex_unlock(mutex);
        return SUCCESS;
    }
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
        // abort();
    }
    struct hostent *host;
    struct sockaddr_in addr;
    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        return NULL;
        // abort();
    }
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SSL_PORT);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        // close(sockfd);

        perror(hostname);
        return NULL;
        // abort();
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
        return GETADDRINFO_ERR;
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
        return BIND_SOCKET_FAIL;
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

int db_insert_href(char *protocol, char *hostname, char *path, char *next_url) {
    char url[URL_LEN];
    if (is_full()) return FAIL;
    if (strstr(next_url, "http") != NULL) {
        strncpy(url, next_url, URL_LEN);

    } else if (next_url[0] == '/' && next_url[1] == '/') {
        snprintf(url, URL_LEN, "%s:%s", protocol, next_url);

    } else if (next_url[0] == '/') {
        snprintf(url, URL_LEN, "%s://%s%s", protocol, hostname, next_url);

    } else {
        snprintf(url, URL_LEN, "%s://%s%s%s", protocol, hostname, path, next_url);
    }
    if (is_visited(url)) {
        return FAIL;
    }

    enqueue(url);

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