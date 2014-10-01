#include "tinymq.c"
#ifdef __cplusplus
extern "C" {
#endif

// Command line parsing
struct arg_t {
    const char* ip_address;
    int port_number;
    const char* log_option;
};

static const char* HELP = "--addr : ip address \n --port : port number --log-option: log option of/f/o/<null> \n";

int parse_arg( struct arg_t* out , int argc , char** argv ) {
    if( argc != 7 && argc != 5  ) {
        printf("%s",HELP);
        return -1;
    } else {
        int i;
        out->log_option = NULL;
        for( i = 1 ; i < argc ; i+=2 ) {
            if( strcmp(argv[i],"--addr") == 0 ) {
                out->ip_address = argv[i+1];
            } else if( strcmp( argv[i] , "--port") == 0 ) {
                errno = 0;
                out->port_number = strtol(argv[i+1],NULL,10);
                if( errno != 0 ) {
                    printf("%s",HELP);
                    return -1;
                }
            } else if( strcmp(argv[i] , "--log-option") == 0 ) {
                out->log_option = argv[i+1];
            } else {
                printf("%s",HELP);
                return -1;
            }
        }
        return 0;
    }
}

int main( int argc , char** argv ) {
    struct arg_t arg;
    char addr[128];
    if( parse_arg(&arg,argc,argv) != 0 )
        return -1;
    sprintf(addr,"%s:%d",arg.ip_address,arg.port_number);
    net_init();
    return tinymq_start( addr , arg.log_option );
}

#ifdef __cplusplus
}
#endif // __cplusplus
