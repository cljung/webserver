#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _MSC_VER
#include <arpa/inet.h>
#include <dirent.h>
#include <pthread.h>
#include <netinet/in.h>
#include <regex.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4996) 
#define __WSA_CALLS
#define WIN32_LEAN_AND_MEAN
#define WS_VERSION_REQD    0x0202
#include <signal.h>
#include <time.h>
#include <windows.h>
#include <winsock2.h>
#pragma comment(lib, "wsock32.lib")
#define ssize_t         size_t
#define socklen_t       int
#define write(h,p,l)    send(h,p,l,0)
#define read(h,p,l)     recv(h,p,l,0)
#define close(h)        closesocket(h)
#define ioctl(h)        ioctlsocket(h)
#define socklen_t		int
#define strcasecmp      stricmp
#endif

#define DIM(x) (int)(sizeof(x)/sizeof(x[0]))
#define BUFFER_SIZE 104857600
#define WEBSERVER_NAME "Tiny Webserver"

int gPort = 3000;
char gLocalPath[256] = "./";
char gStartPage[256] = "index.html";
int gVerbose = 0;
int gExit = 0;
char gCacheControl[64] = "";
int gnFrequency = 15; // 15 secs
int gIsWindowsOS = 0;

typedef enum {
    HTTP_METHOD_UNKNOWN,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_TRACE
} HttpMethod;

typedef struct {
    HttpMethod method;
    int supported;        
    char* name;
    int length;
} HttpMethodSupported;

HttpMethodSupported httpMethodsSupported[] = {
    { HTTP_METHOD_UNKNOWN, 0, "UNKNOWN", 7 },
    { HTTP_METHOD_GET, 1, "GET", 3 },
    { HTTP_METHOD_HEAD, 1, "HEAD", 4 },
    { HTTP_METHOD_POST, 0, "POST", 4 },
    { HTTP_METHOD_PUT, 0, "PUT", 3 },
    { HTTP_METHOD_PATCH, 0, "PATCH", 5 },
    { HTTP_METHOD_DELETE, 0, "DELETE", 6 },
    { HTTP_METHOD_OPTIONS, 1, "OPTIONS", 7 },
    { HTTP_METHOD_CONNECT, 0, "CONNECT", 7 },
    { HTTP_METHOD_TRACE, 1, "TRACE", 5 }
};

typedef struct {
    HttpMethod          method;         // as above
    char*               request;        // buffer read from socket
    int                 request_len;    // bytes received from client 
    char*               path;           // pointer to request path (ie, /index.html). Not null terminated
    int                 pathlength;     // length of path
    char*               query;          // pointer to query strings (?...)
    int                 querylength;    // length of query strings, if it exists. Not null terminated
    char*               hash;           // pointer to hash (#...)
    int                 hashlength;     // length of hash strings, if it exists. Not null terminated
    char*               headers;        // pointer to headers
    int                 headerlength;   // length of headers strings, if it exists. Not null terminated
    char*               response;       // response buffer to put HTTP response in
    size_t              response_len;   // bytes used in the response buffer
    size_t              responsebufferlength;   // how much memory was allocated in the response buffer
    char*               urlDecodedPath; // the URL decoded path
    char                mimeType[32];   // mime type, derived from file extension
} HttpRequest;

typedef struct {
    char *fileExtension;
    char *mimeType;
} MimeType;

MimeType mimeTypes[] = {
    { "html", "text/html" },
    { "htm", "text/html" },
    { "css", "text/css" },
    { "js", "text/javascript" },
    { "txt", "text/plain" },
    { "jpg", "image/jpeg" },
    { "jpeg", "image/jpeg" },
    { "png", "image/png" },
    { "gif", "image/gif" },
    { "svg", "image/svg+xml" },
    { "json", "application/json" },
    { "xml", "text/xml" }
};

const char *get_mime_type(const char *file_ext) {
    for( int n = 0; n < DIM(mimeTypes); n++ ) {
        if (strcasecmp(file_ext, mimeTypes[n].fileExtension) == 0) { 
            return mimeTypes[n].mimeType;
        }
    }
    return "application/octet-stream";
}

void* allocmem(size_t size) {
    void *p = malloc(size);
    if ( p )
        memset(p, 0, size);
    return p;
}

char* replace_char(char* str, char find, char replace) {
    char* current_pos = strchr(str, find);
    while (current_pos) {
        *current_pos = replace;
        current_pos = strchr(current_pos, find);
    }
    return str;
}

char* url_decode(const char* src) {
    size_t src_len = strlen(src);
    char* decoded = allocmem(src_len + 1);
    size_t decoded_len = 0;

    // decode %2x to hex
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            int hex_val;
            (void)sscanf(src + i + 1, "%2x", &hex_val);
            decoded[decoded_len++] = hex_val;
            i += 2;
        }
        else {
            decoded[decoded_len++] = src[i];
        }
    }
    // add null terminator
    decoded[decoded_len] = '\0';
    return decoded;
}

HttpMethod get_http_method( const char*buffer ){
    for( int n = 0; n < DIM(httpMethodsSupported); n++ ) {
        if (!strncmp( httpMethodsSupported[n].name, buffer, httpMethodsSupported[n].length)  
            && *(buffer+httpMethodsSupported[n].length) == ' ') { 
            return httpMethodsSupported[n].method;
        }
    }
    return HTTP_METHOD_UNKNOWN;
}

const char* get_file_extension(const char* file_name) {
    const char* dot = strrchr(file_name, '.');
    if (!dot || dot == file_name) {
        return "";
    }
    return dot + 1;
}

int read_file_into_buffer(const char* filename, char* buffer) {
    int filesize = 0;
#ifdef _MSC_VER
    FILE* file_fd = fopen(filename, "rb");
    while (!feof(file_fd)) {
        filesize += fread(buffer + filesize, 1, BUFFER_SIZE - filesize, file_fd);
    }
    fclose(file_fd);
#else
    int file_fd = open(filename, O_RDONLY);
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, buffer + filesize, BUFFER_SIZE - filesize)) > 0) {
        filesize += bytes_read;
    }
    close(file_fd);
#endif
    return filesize;
}
char* get_current_date(char* dateString) {
    time_t timestamp;
    time(&timestamp);
    strcpy(dateString, (const char*)asctime(gmtime(&timestamp)));
    replace_char(dateString, '\n', 0);
    return dateString;
}

int get_http_request_details( HttpRequest* request, char* buffer ) {
    memset(request, 0, sizeof(HttpRequest));
    // GET /path?query#hash HTTP/1.1
    request->request = buffer;
    request->request_len = strlen(buffer);
    request->method = get_http_method( buffer );
    if (request->method == HTTP_METHOD_UNKNOWN)
        return 0;
    request->path = buffer + httpMethodsSupported[(int)request->method].length + 1; // +1 for ' ' 
    char* httpVerPos = strstr( request->path, " HTTP/");
    request->pathlength = httpVerPos - request->path;
    request->query = strchr(request->path, '?');
    if (request->query > httpVerPos) // we found something beyond first line
        request->query = 0;
    request->hash = strchr(request->path, '#');
    if (request->hash > httpVerPos) // we found something beyond first line
        request->hash = 0;
    // no query or hash - path is enire string
    if (!request->query && !request->hash) {
        request->pathlength = httpVerPos - request->path;
    }
    else {
        // both query and hash
        if (request->query && request->hash) {
            // query before hash
            if (request->query < request->hash) {
                request->pathlength = request->query - request->path;
                request->querylength = request->hash - request->query;
                request->hashlength = httpVerPos - request->hash;
            } else { // hash before query
                request->pathlength = request->hash - request->path;
                request->hashlength = request->query - request->hash;
                request->querylength = httpVerPos - request->query;
            }
        }
        else {
            // query, no hash
            if (request->query && !request->hash) {
                request->pathlength = request->query - request->path;
                request->querylength = httpVerPos - request->query;
            }
            // hash, no query
            if (!request->query && request->hash) {
                request->pathlength = request->hash - request->path;
                request->hashlength = httpVerPos - request->hash;
            }
        }
    }
    // extract filename from request and decode URL
    int pathlength = request->pathlength;
    char* url_encoded_file_name = request->path;
    if (*url_encoded_file_name == '/') {
        url_encoded_file_name++;
        pathlength--;
    }
    if (pathlength == 0) {
        request->urlDecodedPath = gStartPage;
    } else {
        // temporary null terminate the string
        char tmp = *(url_encoded_file_name + pathlength);
        *(url_encoded_file_name + pathlength) = 0;
        request->urlDecodedPath = url_decode(url_encoded_file_name);
        // change forward slash to backslash - if needed
        if (gIsWindowsOS)
            replace_char(request->urlDecodedPath, '/', '\\');
        *(url_encoded_file_name + pathlength) = tmp;
    }
    // get mime type from file extension
    strcpy(request->mimeType, get_mime_type(get_file_extension(request->urlDecodedPath)));
    // headers
    char* pFirstCRLF = strstr(request->request, "\r\n");
    char* pFirstCRLFCRLF = strstr(request->request, "\r\n\r\n");
    if (pFirstCRLF && pFirstCRLFCRLF) {
        pFirstCRLFCRLF += 4;
        request->headers = pFirstCRLF + 2;
        request->headerlength = pFirstCRLFCRLF - pFirstCRLF;
    }
    return 1;
}

void http_notfound_response(HttpRequest* request) {
    char dateString[64];
    request->response_len += snprintf(request->response, request->responsebufferlength,
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/plain\r\n"
        "Date: %s\r\n"
        "Server: %s\r\n"
        "\r\n"
        "404 Not Found",
        get_current_date(dateString), WEBSERVER_NAME);
}

void http_get_request( HttpRequest* request ) {
    char localFilePath[1024];
    char lastModified[64];
    char dateString[64];

    // map file to local path
    snprintf(localFilePath, DIM(localFilePath), "%s%s", gLocalPath, request->urlDecodedPath );
    if ( gVerbose )
        printf( "Local file path: %s\n\n", localFilePath );

    // if file not exist, response is 404 Not Found
    struct stat file_stat;
    if (stat(localFilePath, &file_stat) != 0) {
        if ( gVerbose )
            printf( "file does not exist\n\n" );
        http_notfound_response(request);
        return;
    }

    // get file size for Content-Length and last modified for Last-Modified
    off_t file_size = file_stat.st_size;
    strcpy(lastModified, (const char*)ctime(&file_stat.st_mtime));
    replace_char( lastModified, '\n', 0 );

    // build the http response header for a 200
    request->response_len += snprintf(request->response, request->responsebufferlength,
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: %s\r\n"
                                    "Content-Length: %ld\r\n"
                                    "%s"
                                    "Date: %s\r\n"
                                    "Last-Modified: %s\r\n"
                                    "Server: %s\r\n"
                                    "\r\n",
                                    request->mimeType, (long)file_size, gCacheControl, get_current_date(dateString), lastModified, WEBSERVER_NAME);

    // if HEAD, skip reading the file
    if (request->method == HTTP_METHOD_GET) {
        int filesize = read_file_into_buffer( localFilePath, request->response + request->response_len );
        request->response_len += filesize;
    }
}

void http_trace_request(HttpRequest* request) {
    char dateString[64];    

    // build the http response header for a 200
    request->response_len += snprintf(request->response, request->responsebufferlength,
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: message/http\r\n"
                                    "Content-Length: %d\r\n"
                                    "Date: %s\r\n"
                                    "Server: %s\r\n"
                                    "\r\n"
                                    "%s",
                                    request->request_len, get_current_date(dateString), WEBSERVER_NAME, request->request );
}

void http_options_request( HttpRequest* request ) {
    char dateString[64];

    // build the http response header for a 204
    request->response_len += snprintf(request->response, request->responsebufferlength,
                                    "HTTP/1.1 204 No Content\r\n"
                                    "Allow: OPTIONS, GET, HEAD, TRACE\r\n"
                                    "%s"
                                    "Date: %s\r\n"
                                    "Server: %s\r\n"
                                    "\r\n",
                                    gCacheControl, get_current_date(dateString), WEBSERVER_NAME );
}

void http_method_not_allowed( HttpRequest* request ) {
    char dateString[64];    
    char message[64];
    snprintf(message, DIM(message), "Method not allowed - %s", httpMethodsSupported[(int)(request->method)].name);
    // build the http response header for a 400
    request->response_len += snprintf(request->response, request->responsebufferlength,
                                    "HTTP/1.1 405 Method Not Allowed\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "Content-Length: %d\r\n"
                                    "Date: %s\r\n"
                                    "Server: %s\r\n"
                                    "\r\n"
                                    "%s",
                                    (int)strlen(message), get_current_date(dateString), WEBSERVER_NAME, message);
}

int is_keep_alive_set( HttpRequest* request ) {
    if ( request->headers == NULL )
        return 0;
    char* p = strstr( request->headers, "Connection: Keep-Alive" );
    if (!p)
        p = strstr( request->headers, "Connection: keep-alive" );
    if ( !p || (p && p > (request->headers + request->headerlength)) )
        return 0;
    char *pEnd = strstr( p, "\r\n" );
    return ( p && p < pEnd );
}

void *handle_client(void *arg) {
    int client_fd = (int)(long)arg;
    HttpRequest httpRequest;
    char *buffer = (char *)allocmem(BUFFER_SIZE * sizeof(char));

    // set timeout
#ifdef _MSC_VER
    DWORD timeout = gnFrequency * 1000; // ms
#else
    struct timeval timeout;
    timeout.tv_sec = gnFrequency; // sec
    timeout.tv_usec = 0;
#endif
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if ( gVerbose )
        printf( "socket %d listening with timeout %d\n", client_fd, gnFrequency );


    int fSocketKeepAlive = 0;
    do {
        // receive request data from client and store into buffer
        ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_received > 0 && bytes_received < BUFFER_SIZE) {
            get_http_request_details( &httpRequest, buffer );
            if (gVerbose)
                printf("%s", buffer);
            // alloc HTTP response buffer. GET requires a big response buffer, the other smaller
            if (httpRequest.method == HTTP_METHOD_GET)
                httpRequest.responsebufferlength = BUFFER_SIZE * 2 * sizeof(char);
            else httpRequest.responsebufferlength = BUFFER_SIZE; // max(httpRequest.request_len, 32767);
            httpRequest.response = allocmem( httpRequest.responsebufferlength );

            switch (httpRequest.method) {
                case HTTP_METHOD_GET:
                case HTTP_METHOD_HEAD:
                    http_get_request( &httpRequest );
                    break;
                case HTTP_METHOD_OPTIONS:
                    http_options_request( &httpRequest );
                    break;
                case HTTP_METHOD_TRACE:
                    http_trace_request( &httpRequest );
                    break;
                default:
                    http_method_not_allowed( &httpRequest );
            }

            if (gVerbose) {
                char* pEnd = strstr(httpRequest.response, "\r\n\r\n");
                int len = pEnd - httpRequest.response;
                printf("%*.*s\n\n", len, len, httpRequest.response);
            }

            // send HTTP response to client
            send(client_fd, httpRequest.response, httpRequest.response_len, 0);

            fSocketKeepAlive = is_keep_alive_set( &httpRequest );

            free(httpRequest.response);
            if ( httpRequest.urlDecodedPath != gStartPage)
                free(httpRequest.urlDecodedPath);
            memset(buffer, 0, BUFFER_SIZE);
        }
        // socket error/timeout)
        if ( bytes_received <= 0 || bytes_received >= BUFFER_SIZE)
            fSocketKeepAlive = 0;
        
        if ( gVerbose && fSocketKeepAlive )
            printf( "socket Keep-Alive %d\n", client_fd );

    } while( fSocketKeepAlive );

    if ( gVerbose )
        printf( "socket close %d\n", client_fd );
    close(client_fd);
    free(buffer);
    return NULL;
}

void parse_args( int argc, char *argv[] ) {
	for (int n = 1; n < argc; n++) {
        if ( !strcmp(argv[n], "-p") || !strcmp(argv[n], "--port" ) && n+1 <= argc ) 
            gPort = atoi(argv[++n]);

        if ( !strcmp(argv[n], "-f") || !strcmp(argv[n], "--frequency" ) && n+1 <= argc ) 
            gnFrequency = atoi(argv[++n]);

        if ( !strcmp(argv[n], "-d") || !strcmp(argv[n], "--dir" ) && n+1 <= argc ) {
            strcpy( gLocalPath, argv[++n] );
            int len = strlen(gLocalPath);
            if (!(gLocalPath[len-1] == '/' || gLocalPath[len-1] == '\\'))
                strcat(gLocalPath, "/" );
        }

        if ( !strcmp(argv[n], "-s") || !strcmp(argv[n], "--startpage" ) && n+1 <= argc )
            strcpy( gStartPage, argv[++n] );

        if ( !strcmp(argv[n], "-v") || !strcmp(argv[n], "--verbose" ) )
            gVerbose = 1;

        if ( !strcmp(argv[n], "-nc") || !strcmp(argv[n], "--no-cache" ) ) {
            strcpy( gCacheControl, "Cache-Control: no-cache\r\n" );
        }

        if (*(argv[1] + 1) == '?' || *(argv[1] + 1) == 'h') {
            printf("webserver version 1.00\n\n"
                "Light webserver only supporting GET and static files\n\n"
                "syntax: webserver [-p 3000] [-d path] [-s default page] [-nc] [-f 30] [-v]\n"
                "\n"
                "-p sets the TCP port to listen too. Default is 3000\n"
                "\n"
                "-f TCP poll frequency and keep-alive timeout in seconds. Default is 15\n"
                "\n"
                "-d Sets the local path to serve static files from. Default is none\n"
                "\n"
                "-s Sets the default start page. Default is index.html\n"
                "\n"
                "-nc Cache-Control: no-cache on responses. Default is don't return Cache-Control\n"
                "\n"
                "-v Verbose mode\n"
            );
            exit(0);
        }
	}
}

void signal_handler(int s){
    printf("Caught signal %d. Exiting...\n",s );
    gExit = 1;
}

void server_listener( int server_fd ) {
    fd_set readfds, testfds;
    int fd, n, result, client_fd;
	struct timeval	tv;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    signal(SIGINT, signal_handler);

    while( !gExit ) {
        tv.tv_sec = gnFrequency;
        tv.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_ZERO(&testfds);
        FD_SET(server_fd, &readfds);
        testfds = readfds;

        result = select( FD_SETSIZE, &testfds, (fd_set *)0, (fd_set *)0, (struct timeval *) &tv);
        // socket error
        if ( result < 0 ) {
            break;
        }
        // timeout occured - loop again
        if ( result == 0 ) {
            continue;
        }
#ifdef _MSC_VER
        for (n = 0; n < (int)testfds.fd_count; n++) {
            if (testfds.fd_array[n] > 0) {
                fd = testfds.fd_array[n];
#else
        for(fd = 0; fd < FD_SETSIZE; fd++) {
            if( FD_ISSET(fd,&testfds) )	{
#endif
                client_addr_len = sizeof(client_addr);
                // accept client connection
                if ((client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
                    perror("accept failed");
                    continue;
                }
                // create a new thread to handle client request
#if (defined _MSC_VER)
                HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)handle_client, (void *)(long)client_fd, 0, NULL);
                CloseHandle(hThread);
#else                
                pthread_t thread_id;
                pthread_create(&thread_id, NULL, handle_client, (void *)(long)client_fd);
                pthread_detach(thread_id);
#endif
                FD_SET( fd, &readfds );
                FD_SET( fd, &testfds);
			} // if FD_ISSET
		} // for
    }
}

void exit_failure( int fd, char* message ) {
    if ( fd > 0)
        close(fd);
    perror(message);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    parse_args( argc, argv );

    char* osType = getenv("OS");
    if (osType && !strcmp(osType, "Windows_NT")) {
        gIsWindowsOS = 1;
        replace_char(gLocalPath, '/', '\\' );
    }
    struct stat sb;
    if (stat(gLocalPath, &sb)) {
        exit_failure(-1, gLocalPath);
    }

#ifdef __WSA_CALLS
	// initialize WinSocket under Windows
    WSADATA     wsaData;
    (void)WSAStartup(WS_VERSION_REQD, &wsaData);
#endif

    // create server socket
    int server_fd;
    if ( (server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        exit_failure(server_fd,"socket failed");
    }
    // make socket reusable to avoid "already in use" when restarting app
    const int enable = 1;
    if ( setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable, sizeof(int)) < 0) {
        exit_failure(server_fd, "setsockopt(SO_REUSEADDR) failed");
    }

    // config socket
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(gPort);

    // bind socket to port
    if ( bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 ) {
        exit_failure( server_fd, "bind failed");
    }

    if ( listen(server_fd, 10) < 0 ) {
        exit_failure( server_fd, "listen failed");
    }

    // listen for connections
    printf("Server listening on port %d\n", gPort);
    if (gVerbose ) {
        printf( "Local path:\t%s\nStart page:\t%s\nFrequency:\t%d\nCaching:\t%s\n"
            , gLocalPath, gStartPage, gnFrequency, gCacheControl );
    }

    server_listener( server_fd );

    printf("exiting...\n");

#ifdef __WSA_CALLS
	WSACleanup(); 
#endif
    close(server_fd);
    return 0;
}