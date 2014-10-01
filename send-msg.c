#include <network.h>
#ifdef __APPLE__
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifndef NDEBUG
#define VERIFY assert
#else
#define VERIFY(c) \
    do { \
        if(!(c)) { \
            fprintf(stderr,"%s\n",#c); \
            abort(); \
        } \
    } while(0)
#endif // NDEBUG

// Command argument for send-msg command line tool
// This tool will accept the following options :
// --type PUT/GET
// --addr 127.0.0.1
// --port 12345
// --option T100|L100
// --key Name
// --data "SomeData Here Is the Data"

struct arg_t {
    const char* data;
    size_t data_len;
    const char* addr;
    const char* port;
    const char* key;
    const char* option;
    const char* type;
};

static const char* HELP = "--addr : address \n" \
    "--port : port number\n" \
    "--option : option string for message\n" \
    "--key : key for the message\n" \
    "--data : data for the message\n" \
    "--type : type for the message\n";

int parse_arg( struct arg_t* arg , int argc , char** argv ) {
    int i;
    arg->data = NULL;
    arg->data_len = 0;
    arg->addr = NULL;
    arg->port = NULL;
    arg->key = NULL;
    arg->option = NULL;
    arg->type = NULL;
    if( argc < 11 ) {
        printf("%s",HELP);
        return -1;
    }
    for( i = 2 ; i < argc ; i+= 2 ) {
        if( strcmp(argv[i-1],"--addr") == 0 ) {
            arg->addr = argv[i];
            continue;
        } else if( strcmp(argv[i-1],"--port") == 0 ) {
            // checking the port for safe
            errno = 0;
            strtoul(argv[i],NULL,10);
            if( errno != 0 ) {
                printf("%s",HELP);
                return -1;
            }
            arg->port = argv[i];
            continue;
        } else if( strcmp(argv[i-1],"--option") == 0 ) {
            arg->option = argv[i];
            continue;
        } else if( strcmp(argv[i-1],"--key") == 0 ) {
            arg->key = argv[i];
            continue;
        } else if( strcmp(argv[i-1],"--data") == 0 ) {
            arg->data = argv[i];
            arg->data_len = strlen(arg->data);
            continue;
        } else if( strcmp(argv[i-1],"--type") == 0 ) {
            if( strcmp(argv[i],"GET") != 0 && strcmp(argv[i],"PUT") != 0 ) {
                printf("%s",HELP);
                return -1;
            }
            arg->type = argv[i];
            continue;
        } else {
            printf("%s",HELP);
            return -1;
        }
    }
    if( arg->type != NULL && strcmp(arg->type,"GET") == 0 ) {
        arg->data = NULL;
        arg->data_len = 0;
    }

    if( arg->type == NULL ||
        arg->key == NULL ||
        arg->option == NULL ||
        arg->addr == NULL ||
        arg->port == NULL ) {
            printf("%s\n",HELP);
            return -1;
    }
    return 0;
}

char* format_request( const struct arg_t* arg , int* len ) {
    char header[128];
    int sz = sprintf(header,"%s 1.0 %s %d %s\r\n",arg->type,arg->option,arg->data_len,arg->key);
    char* buf = malloc( sz + arg->data_len );
    memcpy(buf,header,sz);
    if( arg->data_len != 0 && arg->data != NULL )
        memcpy(buf+sz,arg->data,arg->data_len);
    *len = sz + arg->data_len;
    return buf;
}

int parse_reply( char* data , size_t len ) {
    size_t i ;
    char rep[128];
    int sz;
    for( i =  0 ; i < len ; ++i ) {
        if( data[i] == '\r' ) {
            if( i+1 < len && data[i+1] == '\n' ) {
                break;
            } else {
                return -1;
            }
        }
    }
    data[i] = 0;
    if( sscanf(data,"REP 1.0 %s %d",rep,&sz) <=0 ) {
        return -1;
    }
    if( strcmp(rep,"FAIL") == 0 ) {
        printf("%s\n","FAIL");
        return -1;
    } else {
        char* print_data = malloc(sz+1);
        VERIFY(print_data);
        memcpy(print_data,data+i+2,sz);
        print_data[sz] = 0;
        printf("%s\n",print_data);
        return 0;
    }
}

int recv_rep( socket_t fd ) {
    char* buf = malloc(1024);
    size_t cap = 1024;
    size_t sz = 0;
    VERIFY(buf);
    while(1) {
        int n = recv(fd,buf,1024,0);
        if( n == 0 || n < 1024 ) {
            sz+=n;
            return parse_reply(buf,sz);
        } else if( n < 0 ) {
            free(buf);
            return -1;
        } else {
            buf = realloc(buf,cap*2);
            VERIFY(buf);
            cap *= 2;
            sz += 1024;
        }
    }
    return -1;
}

int main( int argc , char** argv ) {
    socket_t fd;
    struct arg_t cmd;
    char addr[128];
    char* req;
    int ret;
    int len;
    net_init();
    if( parse_arg(&cmd,argc,argv) != 0 ) {
        return -1;
    }
    req = format_request(&cmd,&len);
    sprintf(addr,"%s:%s",cmd.addr,cmd.port);
    fd = net_block_client_connect(addr);
    if( fd == -1 ) {
        fprintf(stderr,"Cannot connect to %s\n",addr);
        return -1;
    }
    send(fd,req,len,0);
    ret = recv_rep(fd);
    closesocket(fd);
    return ret;
}

#ifdef __cplusplus
}
#endif // __cplusplus
