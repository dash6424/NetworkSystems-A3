/*
 * Filename: server.c
 * File Description:
 * This file contains the TCP socket implementation for A2.
 * This code has been compiled with GCC using VS Code Editor.
 * Author: Daanish Shariff
 * Reference: I have referenced my own code from AESD course.
 * https://github.com/cu-ecen-aeld/assignments-3-and-later-dash6424/blob/4fa53bfa3ab2770d4fc3e3fdd153001abcd2b5f3/server/aesdsocket.c
 */

 /*==========================================================================
  Include files
========================================================================== */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <syslog.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/fs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/md5.h>

/*==========================================================================
  MACROS
========================================================================== */
#define BACKLOG 15
#define INIT_BUF_SIZE 8192
#define TIME_PERIOD 10
#define SERVER_PORT 80

/*==========================================================================
  Global Declarations
========================================================================== */
int complete_exec = 0;

/* thread arguments */
typedef struct
{
    pthread_t thread_id;
    int client_fd;
    pthread_mutex_t *mutex;
    uint32_t timeout;
}thread_data_t;

/* Client HTTP Request */
typedef struct
{
    char req_method[10];            //Store the Request Method (Eg. GET)
    char http_version[10];          // Store HTTP Version
    char connection_state[50];      // Check connection state
    char req_url[100];              // HTTP URL
    char host[100];                 // HOST (Eg: localhost:8888)
}http_req_t;

/* STATUS Codes */
typedef enum
{
    SUCCESS,
    BAD_REQUEST = -1,
    NOT_FOUND = -2,
    NOT_ALLOWED = -3,
    WRN_VER = -4,
    FORBIDDEN = -5,
}get_status_t;

/* Caching */
typedef struct
{
    char url[MD5_DIGEST_LENGTH * 2 + 1];
    uint32_t timeout;
}cache_t;

typedef struct node
{
    cache_t cache;
    struct node *next;
}node_t;

node_t *head = NULL;

/*==========================================================================
  Function Declaration
========================================================================== */

/* Description: get_http_request
 * Parses the input payload and stores
 * in http request structure.
 *
 * Parameters:
 * buf  : Input buffer from client
 * req	: Client request data populated.
 *
 * Return Type:
 * void : No return type required.
 */
void get_http_request(http_req_t *req, char*buf);

/* Description: get_http_response
 * Validates the client request information
 * Provides the file handler for the file to read
 * Populates the header information in buf.
 *
 * Parameters:
 * buf  : Output buffer to client
 * req	: Client request data.
 * fd   : File descriptor.
 * keepp_alive  : Flag based on connection status.
 *
 * Return Type:
 * int     : 0 on success, -1 on failure status code, -2 on failures.
 */
int validate_client_req(char *buf, http_req_t *req, struct hostent **server);

/* Description: get_content_type
 * Get the file format from the client data.
 *
 * Parameters: 
 * req	: Client request data.
 * buf  : File format output.
 *
 * Return Type:
 * void : No return type required.
 */
void get_content_type(char *buf, char *res_ptr);

/*==========================================================================
  Function Definitions
========================================================================== */

/* Description: sig_handler
 * Signal Handler function to terminate process
 * based on signal received from SIGINT or SIGTERM.
 * Ensure only reentrant calls are made in sig_handler.
 *
 * Parameters:
 * signum	: Holds the signal number received.
 *
 * Return Type:
 * void     : No return type required.
 */
void sig_handler(int signum)
{
    if((signum == SIGINT) || signum == SIGTERM)
    {
        complete_exec = 1;
    }
}

/* Description: signal_init
 * Init signal handler for SIGINT & SIGTERM.
 *
 * Parameters:
 * void     : No parameters required.
 *
 * Return Type:
 * void     : No return type required.
 */
int signal_init()
{
    struct sigaction sig_action;
    sig_action.sa_handler = &sig_handler;

    sigfillset(&sig_action.sa_mask);

    sig_action.sa_flags = 0;

    if(-1 == sigaction(SIGINT, &sig_action, NULL))
    {
        perror("sigaction failed: ");
        exit(0);
    }

    if(-1 == sigaction(SIGTERM, &sig_action, NULL))
    {
        perror("sigaction failed: ");
        exit(0);
    }
    return 0;
}

void compute_md5_checksum(const char *input, unsigned char *md5_checksum) {
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, input, strlen(input));
    MD5_Final(md5_checksum, &context);
}

void generate_unique_string(const char *input, char *unique_string) {
    unsigned char md5_checksum[MD5_DIGEST_LENGTH];
    int i;

    // Compute the MD5 checksum of the input string
    compute_md5_checksum(input, md5_checksum);

    // Convert the MD5 checksum to a hexadecimal string
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&unique_string[i * 2], "%02x", md5_checksum[i]);
    }
    unique_string[MD5_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
}


void payload_to_server(char *in_ptr, char *out_ptr, int len)
{
    int i = 0, j = 0;
    while(in_ptr[i] != 'h')
        out_ptr[j++] = in_ptr[i++];

    while(in_ptr[i] != '.')
        i++;

    while(in_ptr[i] != '/')
        i++;

    while(i < len)
    {
        out_ptr[j++] = in_ptr[i++];
    }
}

/* Description: open_socket
 * Open TCP socket for provided portid
 *
 * Parameters:
 * port_id  : socket to be connected to.
 *
 * Return Type:
 * int      : server socket fd
 */
int open_socket(int port_id)
{
    int listenfd;
    struct sockaddr_in serveraddr;
  
    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Set socket to non blocking */
    int flags = fcntl(listenfd, F_GETFL, 0);
    fcntl(listenfd, F_SETFL, flags | O_NONBLOCK);

    /* timeout the socket port after 10sec */
    // struct timeval sock_opt;
    // sock_opt.tv_sec = 10;
	// sock_opt.tv_usec = 0;
    // if (setsockopt(listenfd, SOL_SOCKET, SO_RCVTIMEO,
    //         (const char*)&sock_opt, sizeof(sock_opt)) < 0)
    //     return -1;

    // reuse the socket port
    int sock_opt = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
            (const char*)&sock_opt, sizeof(sock_opt)) < 0)
        return -1;

    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET; 
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serveraddr.sin_port = htons((unsigned short)port_id); 
    if (bind(listenfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    if (listen(listenfd, BACKLOG) < 0)
        return -1;
    return listenfd;
}

int connect_to_server(char *host)
{
    int sock_status = 0;
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL, *p = NULL;

    memset(&hints, 0, sizeof(hints));   // clear the struct
    hints.ai_family = AF_INET;          // IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP socket

    /* get server info */
    sock_status = getaddrinfo(host, "80", &hints, &servinfo);
    if(0 != sock_status)
    {
        perror("getaddrinfo failure: ");
        return -1;
    }

    if(!servinfo)
    {
        perror("servinfo struct was not populated: ");
        return -1;
    }

    int sfd = -1;
    // Loop through all the results and connect to the first one we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        // Create socket
        sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sfd == -1)
        {
            perror("socket");
            continue;
        }

        struct timeval sock_opt;
        sock_opt.tv_sec = 1;
	    sock_opt.tv_usec = 0;
        setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_opt, sizeof(sock_opt));

        // Connect to server
        if (connect(sfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sfd);
            perror("connect");
            continue;
        }
        break; // If we get here, we successfully connected
    }

    /* Free the addrinfo */
    freeaddrinfo(servinfo);

    if (p == NULL)
    {
        return -1;
    }
    return sfd;
}

node_t *get_cached_node(char *ch)
{
    if(!head)
    {
        return NULL;
    }

    node_t *temp = head, *prev = NULL;

    while(temp)
    {
        if(!strcmp(temp->cache.url, ch))
        {
            break;
        }
        prev = temp;
        temp = temp->next;
    }

    /* If not found return NULL */
    if(!temp)
        return NULL;

    /* check timeout */
    uint32_t timeout = (int)time(NULL);
    printf("Curr time = %d, expiry time = %d\n", timeout, temp->cache.timeout);
    if(timeout > temp->cache.timeout)
    {
        /* Delete the file */
        char dir[100];
        bzero(dir, 100);
        strcat(dir, "./cache/");
        strcat(dir, temp->cache.url);
        remove(dir);
        /* Clear the node */
        temp->cache.timeout = 0;
        bzero(temp->cache.url, MD5_DIGEST_LENGTH * 2 + 1);
        if(prev)
        {
            prev->next = temp->next;
        }
        else //head node
        {
            head = temp->next;
        }
        free(temp);
        temp = NULL;
        return NULL;
    }
    return temp;
}

/* Delete all nodes */
void delete_list()
{
    node_t *temp = NULL;
    while(head)
    {
        temp = head;
        head = head->next;

        /* Clear the node */
        char dir[100];
        bzero(dir, 100);
        strcat(dir, "./cache/");
        strcat(dir, temp->cache.url);
        remove(dir);
        temp->cache.timeout = 0;
        bzero(temp->cache.url, MD5_DIGEST_LENGTH * 2 + 1);
        free(temp);
        temp = NULL;
    }
}

uint8_t check_dyn_page_req(char *str)
{
    if(!str)
        return 0;

    while(*str)
    {
        if(*str++ == '?')
            return 1;
    }
    return 0;
}

typedef struct
{
    pthread_t thread_id;
    http_req_t request;
    char url_ptr[100];
    pthread_mutex_t *mutex;
    uint32_t timeout;
}prefetch_t;

void *thread_prefetch(void *thread_params)
{
    /* Input buffer */
    char in_buf[INIT_BUF_SIZE];
    bzero(in_buf, INIT_BUF_SIZE);

    /* Output buffer */
    char out_buf[INIT_BUF_SIZE];
    bzero(out_buf, INIT_BUF_SIZE);

    /* Detach thread from main */
    pthread_detach(pthread_self());

    /* Parse thread params */
    if(NULL == thread_params)
    {
        return NULL;
    }
    prefetch_t *thread_data = (prefetch_t*)thread_params;

#ifdef DEBUG
    printf("method: %s\n", thread_data->request.req_method);
    printf("version: %s\n", thread_data->request.http_version);
    printf("connection_state: %s\n", thread_data->request.connection_state);
    printf("req_url: %s\n", thread_data->request.req_url);
    printf("host: %s\n", thread_data->request.host);
#endif

   /* Connect socket to server */
    int sfd = connect_to_server(thread_data->request.host);
    if(-1 == sfd)
    {
        goto err_handler;
    }

    /* Populate input buffer */
    char *in_ptr = in_buf;
    memcpy(in_ptr, thread_data->request.req_method, strlen(thread_data->request.req_method));
    in_ptr += strlen(thread_data->request.req_method);
    *in_ptr++ = ' ';
    *in_ptr++ = '/';
    memcpy(in_ptr, thread_data->url_ptr, strlen(thread_data->url_ptr)-1);
    in_ptr += strlen(thread_data->url_ptr)-1;
    *in_ptr++ = ' ';
    memcpy(in_ptr, thread_data->request.http_version, strlen(thread_data->request.http_version));
    in_ptr += strlen(thread_data->request.http_version);
    *in_ptr++ = '\n';

    strcpy(in_ptr, "Host: ");
    in_ptr += strlen("Host: ");
    memcpy(in_ptr, thread_data->request.host, strlen(thread_data->request.host));

#ifdef DEBUG
    printf("PREFETCH BUFFER\n");
    printf("%s\n", in_buf);
#endif

    /* Populate URL */
    bzero(thread_data->request.req_url, sizeof(thread_data->request.req_url));
    strcat(thread_data->request.req_url, thread_data->request.host);
    strcat(thread_data->request.req_url,"/");
    strcat(thread_data->request.req_url, thread_data->url_ptr);

    printf("Prefetch thread connected to %s\n", thread_data->request.req_url);

    /* Send the data to server */
    uint32_t bytes_sent = send(sfd, in_buf, strlen(in_buf), 0);
    if(bytes_sent < 0)
    {
        goto err_handler;
    }

    node_t *new_node = NULL;
    FILE *fp = NULL;

    /* Create a new node to cache the webpage */
    new_node = (node_t *)malloc(sizeof(node_t));
    if(!new_node)
    {
        goto err_handler;
    }
    memset(new_node, 0, sizeof(node_t));
    new_node->next = NULL;

    char url[MD5_DIGEST_LENGTH * 2 + 1];
    /* Check if the webpage is cached */
    bzero(url, MD5_DIGEST_LENGTH * 2 + 1);
    generate_unique_string(thread_data->request.req_url, url);

    /* Copy the url in md5 */
    memcpy(new_node->cache.url, url, (MD5_DIGEST_LENGTH * 2 + 1));

    /* Open file */
    char dir[100];
    bzero(dir, 100);
    strcat(dir, "./cache/");
    strcat(dir, new_node->cache.url);
    fp = fopen(dir, "wb+");
    if(!fp)
    {
        free(new_node);
        perror("file open failed:");
        goto err_handler;
    }
    uint32_t bytes_rcvd = 0;
    /* Receive the HTTP response and also cache it */
    while((bytes_rcvd = recv(sfd, out_buf, INIT_BUF_SIZE, 0)) > 0)
    {
        /* Store it in a file */
        fwrite(out_buf, sizeof(char), bytes_rcvd, fp);
        bzero(out_buf, INIT_BUF_SIZE);
    }
    close(sfd);

    /* Populate new node */
    new_node->cache.timeout = (int)time(NULL) + thread_data->timeout;

    /* Mutex lock */
    if(0 != pthread_mutex_lock(thread_data->mutex))
    {
        perror("lock failed:");
        free(new_node);
        goto err_handler;
    }

    /* Store the new node in linked list */
    new_node->next = head;
    head = new_node;

    /* Mutex unlock */
    if(0 != pthread_mutex_unlock(thread_data->mutex))
    {
        perror("unlock failed:");
        goto err_handler;
    }

err_handler:
    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }
    free(thread_data);
}

void *thread_socket(void *thread_params)
{
    /* Detach thread from main */
    pthread_detach(pthread_self());

    /* Parse thread params */
    if(NULL == thread_params)
    {
        return NULL;
    }
    thread_data_t *thread_data = (thread_data_t*)thread_params;

    /* Input buffer */
    char in_buf[INIT_BUF_SIZE];
    bzero(in_buf, INIT_BUF_SIZE);

    /* Output buffer */
    char out_buf[INIT_BUF_SIZE];
    bzero(out_buf, INIT_BUF_SIZE);

    /* Scratch buffer */
    char data_buf[INIT_BUF_SIZE];
    bzero(data_buf, INIT_BUF_SIZE);

    int bytes_rcvd = 0, bytes_sent = 0, result = 0;
    int total_bytes_sent = 0;

    struct hostent *server_host = NULL;

    /* Receive data from client */
    bytes_rcvd = recv(thread_data->client_fd, in_buf, INIT_BUF_SIZE, 0);
    if(bytes_rcvd <= 0)
    {
        goto err_handler1;
    }

#ifdef DEBUG
    printf("bytes received: %d\n", bytes_rcvd);
    printf("\nINPUT STRING:\n");
    printf("%s\n", in_buf);
#endif

    /* Parse the client request */
    http_req_t client_req = {0};
    get_http_request(&client_req, in_buf);

#ifdef DEBUG
    printf("method: %s\n", client_req.req_method);
    printf("version: %s\n", client_req.http_version);
    printf("connection_state: %s\n", client_req.connection_state);
    printf("req_url: %s\n", client_req.req_url);
    printf("host: %s\n", client_req.host);
#endif

    /* Validate Client Request */
    result = validate_client_req(out_buf, &client_req, &server_host);
    printf("thread_id = 0x%lx, GET HTTP Response Result: %d\n", thread_data->thread_id, result);

    /* NULL check error */
    if(-2 == result)
    {
        goto err_handler1;
    }
    /* Bad client request */
    else if(-1 == result || !server_host)
    {
        /* Send header info to client */
        bytes_sent = send(thread_data->client_fd, out_buf, strlen(out_buf), 0);
        goto err_handler1;
    }

    printf("Client requested URL = %s\n", client_req.req_url);

    /* Check if it's a dynamic webpage request */
    uint8_t is_dyn = check_dyn_page_req(client_req.req_url);
#ifdef DEBUG
    printf("DANDEBUG:url: %s is_dyn = %d\n", client_req.req_url, is_dyn);
#endif

    char url[MD5_DIGEST_LENGTH * 2 + 1];
    /* Cache only static pages */
    if(!is_dyn)
    {
        /* Check if the webpage is cached */
        bzero(url, MD5_DIGEST_LENGTH * 2 + 1);
        generate_unique_string(client_req.req_url, url);

        /* Mutex lock */
        if(0 != pthread_mutex_lock(thread_data->mutex))
        {
            perror("lock failed:");
            goto err_handler1;
        }

        node_t *cached = get_cached_node(url);

        /* Mutex unlock */
        if(0 != pthread_mutex_unlock(thread_data->mutex))
        {
            perror("unlock failed:");
            goto err_handler1;
        }
        if(cached)
        {
            printf("Cache Found!\n");
            char dir[100];
            bzero(dir, 100);
            strcat(dir, "./cache/");
            strcat(dir, cached->cache.url);
            FILE *fp = fopen(dir, "rb+");
            if(!fp)
            {
                perror("cached file open error: ");
                goto err_handler1;
            }
            /* Send the data to the client */
            while((bytes_rcvd = fread(out_buf, sizeof(char), INIT_BUF_SIZE, fp)) > 0)
            {
                bytes_sent = send(thread_data->client_fd, out_buf, bytes_rcvd, 0);
                bzero(out_buf, INIT_BUF_SIZE);
            }
            fclose(fp);
            fp = NULL;
            goto err_handler1;
        }
    }

    /* Update the input string */
    payload_to_server(in_buf, data_buf, strlen(in_buf));

#ifdef DEBUG
    printf("\nSTRING TO SERVER:\n");
    printf("%s\n", data_buf);
#endif

    /* Connect socket to server */
    int sfd = connect_to_server(client_req.host);
    if(-1 == sfd)
    {
        goto err_handler1;
    }

    printf("Connected to %s\n", client_req.host);

    /* Send the data to server */
    bytes_sent = send(sfd, data_buf, strlen(data_buf), 0);
    if(bytes_sent < 0)
    {
        goto err_handler;
    }

    node_t *new_node = NULL;
    FILE *fp = NULL;
    /* Cache only static webpages */
    if(!is_dyn)
    {
        /* Create a new node to cache the webpage */
        new_node = (node_t *)malloc(sizeof(node_t));
        if(!new_node)
        {
            goto err_handler;
        }
        memset(new_node, 0, sizeof(node_t));
        new_node->next = NULL;

        /* Copy the url in md5 */
        memcpy(new_node->cache.url, url, (MD5_DIGEST_LENGTH * 2 + 1));

        /* Open file */
        char dir[100];
        bzero(dir, 100);
        strcat(dir, "./cache/");
        strcat(dir, new_node->cache.url);
        fp = fopen(dir, "wb+");
        if(!fp)
        {
            free(new_node);
            perror("file open failed:");
            goto err_handler;
        }
    }

    /* Prefetch buffer */
    char *pre_fetch = NULL;
    uint32_t prefetch_size = 0;
    /* Receive the HTTP response and also cache it */
    bzero(out_buf, INIT_BUF_SIZE);
    while((bytes_rcvd = recv(sfd, out_buf, INIT_BUF_SIZE, 0)) > 0)
    {
        
        pre_fetch = (char *)realloc(pre_fetch, (prefetch_size+bytes_rcvd));
        if(!pre_fetch)
            goto err_handler;
        memcpy((pre_fetch+prefetch_size), out_buf, bytes_rcvd);
        prefetch_size += bytes_rcvd;

        if(!is_dyn)
        {
            /* Store it in a file */
            fwrite(out_buf, sizeof(char), bytes_rcvd, fp);
        }
        /* Send it to the client as well */
        bytes_sent = send(thread_data->client_fd, out_buf, bytes_rcvd, 0);
        bzero(out_buf, INIT_BUF_SIZE);
    }

#ifdef DEBUG
    printf("SERVER RESPONSE:\n");
    printf("%s\n", pre_fetch);
#endif

    char *ptr = pre_fetch;
    char *search_str = "<a href=\"";
    uint32_t search_str_len = strlen(search_str);

    while((ptr = strstr(ptr, search_str)) != NULL)
    {
        ptr += search_str_len;

        char *end_ptr = strchr(ptr, '\"');
        if(!end_ptr)
            break;

        uint32_t url_len = end_ptr - ptr;
        prefetch_t *prefetch_node = (prefetch_t *)malloc(sizeof(prefetch_t));
        memset(prefetch_node, 0, sizeof(prefetch_t));
        strncpy(prefetch_node->url_ptr, ptr, url_len);
        prefetch_node->url_ptr[url_len] = '\0';
        prefetch_node->mutex = thread_data->mutex;
        memcpy(&(prefetch_node->request), &client_req, sizeof(http_req_t));
        prefetch_node->timeout = thread_data->timeout;

        /* Create a new thread */
        int res = pthread_create(&(prefetch_node->thread_id), NULL, thread_prefetch, prefetch_node);
        if(res == 0)
        {
            printf("Prefetch thread create successful. thread = 0x%lx\n", prefetch_node->thread_id);
        }
        else
        {
            perror("pthread create failed: ");
            free(prefetch_node);
            break;
        }
        ptr = end_ptr + 1;
    }

    if(pre_fetch)
    {
        free(pre_fetch);
        pre_fetch = NULL;
    }

    if(!is_dyn)
    {
        fclose(fp);
        fp = NULL;
        /* Populate new node */
        new_node->cache.timeout = (int)time(NULL) + thread_data->timeout;

        /* Mutex lock */
        if(0 != pthread_mutex_lock(thread_data->mutex))
        {
            perror("lock failed:");
            free(new_node);
            goto err_handler;
        }

        /* Store the new node in linked list */
        new_node->next = head;
        head = new_node;

        /* Mutex unlock */
        if(0 != pthread_mutex_unlock(thread_data->mutex))
        {
            perror("unlock failed:");
            goto err_handler;
        }
    }

err_handler:
    /* Close Server fd */
    close(sfd);

err_handler1:
    /* Close client fd */
    close(thread_data->client_fd);
    printf("Thread destroyed successful. thread = 0x%lx\n", thread_data->thread_id);

    /* free thread data */
    thread_data->client_fd = 0;
    thread_data->thread_id = 0;
    free(thread_data);
    thread_data = NULL;
    return NULL;
}

get_status_t check_blocklist(char *ch)
{
    char buf[INIT_BUF_SIZE];
    bzero(buf, INIT_BUF_SIZE);
    FILE *fp = fopen("blockilist", "r");
    if(!fp)
        return FORBIDDEN;

    fread(buf, sizeof(char), INIT_BUF_SIZE, fp);

    /* Check if the string is present */
    if(strstr(buf, ch))
    {
        fclose(fp);
        return FORBIDDEN;
    }
    fclose(fp);
    return SUCCESS;
}

get_status_t get_host(http_req_t *req, struct hostent **server)
{
    *server = NULL;

    /* Verify method */
    if(req->req_method[0] == '\0')
    {
        printf("input string could not be parsed");
        return BAD_REQUEST;
    }
    if(strcmp(req->req_method, "GET"))
    {
        printf("Invalid Request Method: %s. Supports only GET\n", req->req_method);
        return NOT_ALLOWED;
    }

    /* Verify version */
    uint32_t x = 0, y = 0, cnt = 0;
    cnt = sscanf(req->http_version, "HTTP/%d.%d",&x,&y);
    if((2 != cnt) || (x > 1) || (y > 1))
    {
        printf("Invalid Version %d/%d\n", x,y);
        return WRN_VER;
    }

    /* Validate if host is bloklisted */
    get_status_t status = check_blocklist(req->host);
    if(SUCCESS != status)
    {
        return status;
    }

    /* Get host by name */
    *server = gethostbyname(req->host);
    if (*server == NULL)
    {
        printf("gethostbyname: Host not found \n");
        return NOT_ALLOWED;
    }

    /* Check for valid IP address */
    if((*server)->h_addr_list[0] == NULL)
    {
        printf("Host could not resolve into a valid IP address \n");
        return NOT_FOUND;
    }

    /* Validate if IP address is bloklisted */
    char ip_address[30];
    strcpy(ip_address, inet_ntoa(*(struct in_addr*)(*server)->h_addr));
    status = check_blocklist(ip_address);
    if(SUCCESS != status)
    {
        return status;
    }
    return SUCCESS;
}

int validate_client_req(char *buf, http_req_t *req, struct hostent **server)
{
    if(!buf || !req || !server)
        return -2;

    get_status_t status = get_host(req, server);
    if(NOT_ALLOWED == status)
    {
        /* Copy status */
        char *data = "400 bad request";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content type */
        data = "Content-Type: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        data = "text/html";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content length */
        data = "Content-Length: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        /* Copy content length */
        data = "<html><head><title>400 Bad Request</title></head><body><h2>The request could not be parsed or is malformed</h2></body></html>";
        int len = strlen(data);

        sprintf(buf, "%d", len);
        while(len)
        {
            len = len/10;
            buf++;
        }
        *buf++ = '\r';
        *buf++ = '\n';
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy data */
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        return -1;
    }
    else if(NOT_FOUND == status)
    {
        char *data = "404 Not Found";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content type */
        data = "Content-Type: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        data = "text/html";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content length */
        data = "Content-Length: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        /* Copy content length */
        data = "<html><head><title>404 Not Found</title></head><body><h2>The requested IP address could not be resolved</h2></body></html>";
        int len = strlen(data);

        sprintf(buf, "%d", len);
        while(len)
        {
            len = len/10;
            buf++;
        }
        *buf++ = '\r';
        *buf++ = '\n';
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy data */
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        return -1;
    }
    else if(FORBIDDEN == status)
    {
        char *data = "403 Forbidden";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content type */
        data = "Content-Type: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        data = "text/html";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content length */
        data = "Content-Length: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        /* Copy content length */
        data = "<html><head><title>403 Forbidden</title></head><body><h2>The requested file can not be accessed due to a file permission issue</h2></body></html>";
        int len = strlen(data);

        sprintf(buf, "%d", len);
        while(len)
        {
            len = len/10;
            buf++;
        }
        *buf++ = '\r';
        *buf++ = '\n';
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy data */
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        return -1;
    }
    else if(BAD_REQUEST == status)
    {
        char *data = "400 Bad Request";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content type */
        data = "Content-Type: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        data = "text/html";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content length */
        data = "Content-Length: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        /* Copy content length */
        data = "<html><head><title>400 Bad Request</title></head><body><h2>The request could not be parsed or is malformed</h2></body></html>";
        int len = strlen(data);

        sprintf(buf, "%d", len);
        while(len)
        {
            len = len/10;
            buf++;
        }
        *buf++ = '\r';
        *buf++ = '\n';
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy data */
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        return -1;
    }
    else if(WRN_VER == status)
    {
        char *data = "505 HTTP Version Not Supported";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content type */
        data = "Content-Type: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        data = "text/html";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy Content length */
        data = "Content-Length: ";
        memcpy(buf, data, strlen(data));
        buf += strlen(data);

        /* Copy content length */
        data = "<html><head><title>505 HTTP Version Not Supported</title></head><body><h2>An HTTP version other than 1.0 or 1.1 was requested</h2></body></html>";
        int len = strlen(data);

        sprintf(buf, "%d", len);
        while(len)
        {
            len = len/10;
            buf++;
        }
        *buf++ = '\r';
        *buf++ = '\n';
        *buf++ = '\r';
        *buf++ = '\n';

        /* Copy data */
        memcpy(buf, data, strlen(data));
        buf += strlen(data);
        return -1;
    }
    /* Success */
    return 0;
}

void get_content_type(char *buf, char *res_ptr)
{
    if(!buf || !res_ptr)
        return;

    char file_type[50] = {0};
    int i = strlen(buf) - 1;
    if (strlen(buf) == 1 && buf[0] == '/')
    {
        strcpy(file_type, "html");
    }
    else
    {
        while(buf[i] != '.')
        {
            i--;
        }
        i += 1; int j = 0;
        while(buf[i] != '\0') 
        {
            file_type[j++] = buf[i++];
        }
        file_type[j] = '\0';
    }
    printf("requested file type %s \n", file_type);
    if (strcmp(file_type, "html") == 0)
    {
        strcpy(res_ptr, "text/html");
    }
    else if (strcmp(file_type, "txt") == 0)
    {
        strcpy(res_ptr, "text/plain");
    }
    else if (strcmp(file_type, "png") == 0)
    {
        strcpy(res_ptr, "image/png");
    }
    else if (strcmp(file_type, "gif") == 0)
    {
        strcpy(res_ptr, "image/gif");
    }
    else if (strcmp(file_type, "jpg") == 0)
    {
        strcpy(res_ptr, "image/jpg");
    }
    else if (strcmp(file_type, "ico") == 0)
    {
        strcpy(res_ptr, "image/x-icon");
    }    
    else if (strcmp(file_type, "css") == 0)
    {
        strcpy(res_ptr, "text/css");
    }
    else if (strcmp(file_type, "js") == 0)
    {
        strcpy(res_ptr, "application/javascript");
    }
    else
    {
        strcpy(res_ptr, "text/html");
    }
}

void get_http_request(http_req_t *req, char *buf)
{
    if(!buf)
    {
        req->req_method[0] = '\0';
        return;
    }
    
    int len = strlen(buf);

    uint32_t i = 0, j = 0;

    /* Copy request method */
    while((i < len) && (buf[i] != ' '))
    {
        req->req_method[j++] = buf[i++];
    }
    req->req_method[j] = '\0'; i++;

    /* Copy request url */
    j = 0;
    while((i < len) && (buf[i] != ' '))
    {
        req->req_url[j++] = buf[i++];
    }
    req->req_url[j] = '\0'; i++;

    /* Copy Request version */
    j = 0;
    while((j < 8) && (i < len))
    {
        req->http_version[j++] = buf[i++];
    }
    req->http_version[j] = '\0';
    
    /* Copy Host */
    j = 0; i = i + 2;
    if(buf[i] == 'H')
    {
        i += 6; //HOST: //
        while((i < len) && (buf[i] != '\r'))
        {
            req->host[j++] = buf[i++];
        }
        req->host[j] = '\0';
        j = 0;
    }

    /* Copy connection */
    while((i < (len-2)) && (buf[i] != 'C' || buf[i+1] != 'o' || buf[i+2] != 'n'))
        i++;

    if(i < len)
    {
        i += 12; // "Connection: "
        while(buf[i] != '\r')
        {
            req->connection_state[j++] = buf[i++];
        }
        req->connection_state[j] = '\0';
    }
}


/* Description: main
 * Main function for socket implementation.
 *
 * Parameters:
 * argc     : argument count.
 * argv     : argument string array.
 *
 * Return Type:
 * int     : 0 on success. -1 on error.
 */
int main(int argc, char **argv)
{

    if (argc != 3) {
        fprintf(stderr, "usage: %s <port> <timeout>\n", argv[0]);
        exit(0);
    }
    int port = atoi(argv[1]);
    uint32_t timeout = atoi(argv[2]);

    int sfd = open_socket(port);
    if(sfd == -1)
    {
        printf("error in socket connection\n");
        exit(0);
    }

    /* Signal init */
    if(0 != signal_init())
    {
        printf("initializing signal handler failed\n");
        return -1;
    }

    struct sockaddr_in test_addr;          // Test addr to populate from accept()
    socklen_t addr_size = sizeof(test_addr);    // Size of test addr

    /* Mutex init */
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);

    while(!complete_exec)
    {
        // Connection with the client
        int client_fd = accept(sfd, (struct sockaddr *)&test_addr, &addr_size);
        if((client_fd == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
        {
            continue;                           // Try again
        }
        else if(client_fd == -1)
        {
            perror("accept failure: ");
            break;
        }

        thread_data_t *thread_data = (thread_data_t *)malloc(sizeof(thread_data_t));
        if(!thread_data)
        {
            break;
        }
        memset(thread_data, 0, sizeof(thread_data_t));
        thread_data->client_fd = client_fd;
        thread_data->mutex = &mutex;
        thread_data->timeout = timeout;

        /* Create a new thread */
        int res = pthread_create(&(thread_data->thread_id), NULL, thread_socket, thread_data);
        if(res == 0)
        {
            printf("Thread create successful. thread = 0x%lx\n", thread_data->thread_id);
        }
        else
        {
            perror("pthread create failed: ");
            free(thread_data);
            break;
        }
    }

    //cleanup.
    if(-1 == close(sfd))
    {
        perror("close sfd failed: ");
    }

    pthread_mutex_lock(&mutex);

    /* Delete List */
    delete_list();
    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);

    return 0;
}