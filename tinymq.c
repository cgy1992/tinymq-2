#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#ifndef __APPLE__
#include <malloc.h>
#endif // __APPLE__
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <network.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <arpa/inet.h>
#include <signal.h>
#endif

#define MINOR_VERSION 0
#define MAJOR_VERSION 1

// Message/MessageTable

#define MAX_MSGNAME_LEN 63
#define INIT_MSGTABLE_LEN 1024
#define REHASH_FACTOR 3

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef NDEBUG
#define VERIFY assert
#else
#define VERIFY(x) \
    do { \
    if(!(x)){ \
    fprintf(stderr,"#x failed"); \
    abort(); \
    } \
    } while(0)
#endif // NDEBUG

enum {
    LOG_NOLOG = 0,
    LOG_FILE =  1<<0,
    LOG_STDOUT = 1<<1,
    LOG_STDOUT_AND_FILE = LOG_FILE|LOG_STDOUT
};
int LOG_OPTION = LOG_NOLOG;


// Log function
enum {
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
};

void msg_log( int loglevel , const char* fmt , ... ) {
    FILE* file;
    va_list vlist;
    if( LOG_OPTION == LOG_NOLOG )
        return;
    if( LOG_OPTION & LOG_FILE ) {
        va_start(vlist,fmt);
        switch(loglevel) {
        case LOG_INFO:
            file = fopen("tinymq.log.info.txt","a+");
            VERIFY( file != NULL );
            fprintf(file,"[INFO]:");
            break;
        case LOG_WARN:
            file = fopen("tinymq.log.warn.txt","a+");
            VERIFY( file != NULL );
            fprintf(file,"[WARN]:");
            break;
        case LOG_ERROR:
            file = fopen("tinymq.log.error.txt","a+");
            VERIFY( file != NULL );
            fprintf(file,"[ERROR]:");
            break;
        default: assert(0) ; return;
        }
        vfprintf(file,fmt,vlist);
        fclose(file);
    }
    if( LOG_OPTION & LOG_STDOUT ) {
        va_start(vlist,fmt);
        switch(loglevel) {
        case LOG_INFO:
            printf("[INFO]:");
            vprintf(fmt,vlist);
            break;
        case LOG_WARN:
            printf("[WARN]:");
            vfprintf(stderr,fmt,vlist);
            fflush(stderr);
            break;
        case LOG_ERROR:
            printf("[ERROR]:");
            vfprintf(stderr,fmt,vlist);
            fflush(stderr);
            break;
        default: assert(0) ; return;
        }
    }
}

struct msg_t {
    size_t fullhash;
    void* data; // data value
    char name[MAX_MSGNAME_LEN+1];
    struct msg_t* next;
    struct msg_t* prev;
};

// Chain for resolving the collision
struct msg_bucket_t {
    struct msg_t entry;
};

struct msg_table_t {
    struct msg_bucket_t* buckets;
    size_t cap;
    size_t size;
};

#define MSG_TABLE_INIT_BUCKET(b) \
    do { \
        (b)->entry.prev = &((b)->entry); \
        (b)->entry.next = &((b)->entry); \
    } while(0)

#define MSG_TABLE_INSERT(t,x) \
    do { \
        (t)->prev->next = (x); \
        x->prev = (t)->prev; \
        x->next = (t); \
        (t)->prev= (x); \
    } while(0)


void _msg_table_alloc( struct msg_table_t* table , size_t cap ) {
    size_t i;
    table->buckets = malloc( sizeof(struct msg_bucket_t)*cap );
    VERIFY(table->buckets != NULL);
    table->cap = cap;
    for( i = 0 ; i < cap ; ++i ) {
        MSG_TABLE_INIT_BUCKET(table->buckets+i);
    }
}

size_t _msg_table_hash( const char* name ) {
    size_t val = 0;
    size_t len = strlen(name);
    size_t i ;
    for( i = 0 ; i < len ; ++i ) {
        val = val ^ ((val<<5)+(val>>2)+(size_t)name[i-1]);
    }
    return val;
}

void msg_table_init( struct msg_table_t* table ) {
    _msg_table_alloc(table,INIT_MSGTABLE_LEN);
    table->size =0;
}

// Query the slot in the table based on the struct msg_t*, if we have full
// hash value for the string sequence

struct msg_t*
_msg_table_query_slot( struct msg_table_t* table , struct msg_t* msg , int* use ) {
    struct msg_bucket_t* bucket;
    size_t bucket_pos;
    struct msg_t* slot;
    bucket_pos = msg->fullhash & (table->cap-1);
    bucket = table->buckets + bucket_pos;
    slot = &(bucket->entry);
    for( ; slot != &(bucket->entry) ; slot = slot->next ) {
        if( slot->fullhash == msg->fullhash &&
            strcmp(slot->name,msg->name) == 0 ) {
                *use = 1;
                return slot;
        }
    }
    *use = 0;
    return &(bucket->entry);
}

// This function will perform rehash when the hash function is full
void _msg_table_rehash( struct msg_table_t* table ) {
    struct msg_table_t new_table;
    struct msg_t* slot;
    size_t i;
    int use;
    msg_log(LOG_INFO,"Rehash the message queue:%d",table->cap*2);
    _msg_table_alloc(&new_table, table->cap * 2 );
    // Insert each object from old table to the new table
    for( i = 0 ; i < table->cap ; ++i ) {
        for ( slot = (table->buckets[i].entry.next) ;
              slot != &(table->buckets[i].entry) ;
              slot = slot->next ) {
            struct msg_t* tail = _msg_table_query_slot(&new_table,slot,&use);
            MSG_TABLE_INSERT(tail,slot);
            assert(use ==0);
        }
    }
    free(table->buckets);
    table->buckets = new_table.buckets;
    table->cap *= 2;
}

int msg_table_insert( struct msg_table_t* table , void* data , const char* name ) {
    struct msg_t msg;
    int use;
    struct msg_t* tail;
    assert(name[0] != 0);
    msg.fullhash = _msg_table_hash(name);
    msg.data = data;
    if( strlen(name) >= MAX_MSGNAME_LEN ) {
        return -1;
    } else {
        strcpy(msg.name,name);
    }
    if( table->size > (REHASH_FACTOR*(table->cap)) ) {
        // We will have a simple rehash which reduce the chain size
        _msg_table_rehash(table);
    }
    tail = _msg_table_query_slot(table,&msg,&use);
    if( use == 0 ) {
        struct msg_t* new_msg = malloc(sizeof(msg));
        VERIFY(new_msg != NULL);
        memcpy(new_msg,&msg,sizeof(*new_msg));
        MSG_TABLE_INSERT(tail,new_msg);
        ++table->size;
        return 0;
    } else {
        return -1;
    }
}

struct msg_t* msg_table_query( struct msg_table_t* table , const char* name ) {
    if( strlen(name) > MAX_MSGNAME_LEN ) {
        return NULL;
    } else {
        int fh = _msg_table_hash(name);
        int bucket_slot = (fh & (table->cap-1));
        struct msg_bucket_t* bucket = table->buckets + bucket_slot;
        struct msg_t* slot = bucket->entry.next;
        for( ; slot != &(bucket->entry) ; slot = slot->next ) {
            if( slot->fullhash == fh && strcmp(slot->name,name) == 0 ) {
                return slot;
            }
        }
        return NULL;
    }
}

int msg_table_remove( struct msg_table_t* table , const char* name , void** data ) {
    struct msg_t* msg = msg_table_query(table,name);
    if( msg == NULL )
        return -1;
    *data = msg->data;
    msg->prev->next = msg->next;
    msg->next->prev = msg->prev;
    free(msg);
    --table->size;
    return 0;
}

// The protocol is a simple text based protocol:
// 1 : PUT 1.0 T1000|L1000 100 Name1
// 2 : --- data ---

// 1 : GET 1.0 T300 Name1
// 2 : --- data ---

// Reply:
// 1 : REP 1.0 OK 100\r\n
// 2 : -- data ----
// Or without body:
// 1: REP 1.0 OK 0\r\n

#define MAX_PROTOCACHE_LEN 128
#define MAX_NAME_LEN 64 // The maximum name
#define MAX_DATA_LEN 1024*1024 // 1MB

enum {
    PROTO_PUT=0,
    PROTO_GET,
    PROTO_TEST // Not ready yet
};

enum {
    PROTO_OPTION_LIMITS = 1,
    PROTO_OPTION_TIMEOUT ,
    PROTO_OPTION_TIMEOUT_OR_LIMITS ,
    PROTO_OPTION_TIMEOUT_AND_LIMITS
};

// Parsing state
enum {
    PROTO_REQUEST_TYPE,
    PROTO_REQUEST_VERSION,
    PROTO_REQUEST_LEN,
    PROTO_REQUEST_OPTION,
    PROTO_REQUEST_NAME,
    PROTO_REQUEST_DATA,
    PROTO_DONE
};

struct proto_parser_t {
    int state;
    int type;    // type
    int major_version; // version number
    int minor_version;
    const char* name;
    void* data;
    size_t data_size;
    size_t data_len;
    int limits;
    int timeout;
    int option_type;
    // Cache for the partial data
    char cache[MAX_PROTOCACHE_LEN];
    size_t cache_size;
};

#define proto_parser_init(p) \
    do { \
        (p)->state = PROTO_REQUEST_TYPE; \
        (p)->type = -1; \
        (p)->major_version = 0; \
        (p)->minor_version = 0; \
        (p)->name = NULL; \
        (p)->data = NULL; \
        (p)->data_len =0; \
        (p)->cache_size =0; \
        (p)->data_size=0; \
        (p)->limits=(p)->timeout=0; \
        (p)->option_type=0; \
    } while(0)

enum {
    PROTO_SUCCESS = 0,
    PROTO_ERR_UNKNOWN_TYPE = -1,
    PROTO_ERR_UNKNOWN_VERSION=-2,
    PROTO_ERR_UNKNOWN_DATALEN=-3,
    PROTO_ERR_NO_NAME = -4,
    PROTO_ERR_TOO_LONG_NAME = -6,
    PROTO_ERR_TOO_LARGE_DATA= -7,
    PROTO_ERR_TOO_LARGE_DATALEN=-8,
    PROTO_ERR_TOO_LARGE_OPTION=-9,
    PROTO_ERR_UNKNOWN_OPTION=-10,
    PROTO_ERR_PROTOCOL_UNRECOGNIZE = -100
};

const char* proto_error( int err_code ) {
    switch(err_code) {
    case PROTO_ERR_UNKNOWN_TYPE: return "unknown type";
    case PROTO_ERR_UNKNOWN_VERSION: return "unknown version";
    case PROTO_ERR_UNKNOWN_DATALEN: return "unknown data length";
    case PROTO_ERR_NO_NAME: return "no name";
    case PROTO_ERR_TOO_LONG_NAME: return "too long name";
    case PROTO_ERR_TOO_LARGE_DATA: return "too large data";
    case PROTO_ERR_TOO_LARGE_DATALEN: return "too large data length";
    case PROTO_ERR_TOO_LARGE_OPTION: return "too large option value";
    case PROTO_ERR_UNKNOWN_OPTION: return "unknown option value";
    case PROTO_ERR_PROTOCOL_UNRECOGNIZE: return "unknown protocol";
    default: assert(0); return "";
    }
}

// This routine will return the next buffer from the buffer or cache buffer
int _proto_parser_peek_buffer( struct proto_parser_t* parser , void* dest , size_t dest_len , void* ebuf , size_t ebuf_len ) {
    size_t i = 0;
    size_t dest_size = 0;
    char* cdest = (char*)(dest);
    // A quick check
    if( ebuf_len + parser->cache_size < dest_len )
        return -1;
    // From internal cache
    for( ; i < parser->cache_size && dest_size < dest_len ; ++i ) {
        cdest[dest_size++] = parser->cache[i];
    }
    if( dest_size == dest_len ) {
        return 0;
    }
    // From external buffer
    for( i = 0 ; dest_size < dest_len ; ++dest_size , ++i ) {
        cdest[dest_size] = ((char*)(ebuf))[i];
    }
    return i;
}

// This version of function is used to help figure out the variant name
int _proto_parser_peek_buffer_until( struct proto_parser_t* parser , void* dest , size_t buf_sz ,
                                     char cha , void* ebuf , size_t ebuf_len , size_t* len ) {
    size_t i = 0;
    size_t dest_len = 0;
    size_t buffer_sz = buf_sz;
    char* cdest = (char*)(dest);
    for( ; i < parser->cache_size && buf_sz != 0 ; ++i , -- buf_sz ) {
        cdest[dest_len++] = parser->cache[i];
        if( parser->cache[i] == cha ) {
            *len = dest_len;
            return 0;
        }
    }
    if( buf_sz == 0 ) {
        *len = buffer_sz;
        return -1;
    }
    // Continue our search in the ebuf
    for( i = 0 ; i < ebuf_len && buf_sz != 0 ; ++i , --buf_sz ) {
        cdest[dest_len++] = ((char*)(ebuf))[i];
        if( ((char*)ebuf)[i] == cha ) {
            *len = dest_len;
            return i+1;
        }
    }
    if( buf_sz == 0 ) {
        *len = buffer_sz;
    }
    return -1;
}

// Call this function to make the peek buffer move effects the internal cache
void _proto_parser_commit_buffer( struct proto_parser_t* parser , size_t len ) {
    if( parser->cache_size <= len ) {
        parser->cache_size = 0;
    } else {
        char tmp[MAX_PROTOCACHE_LEN];
        memcpy(tmp,parser->cache+len,parser->cache_size-len);
        memcpy(parser->cache,tmp,parser->cache_size-len);
        parser->cache_size -= len;
    }
}

int _proto_parser_cache_buffer( struct proto_parser_t* parser , void* ebuf , size_t ebuf_len ) {
    if( parser->cache_size + ebuf_len > MAX_PROTOCACHE_LEN ) {
        return -1;
    } else {
        memcpy(parser->cache+parser->cache_size,ebuf,ebuf_len);
        parser->cache_size += ebuf_len;
        return 0;
    }
}

int _proto_request_parse_type( struct proto_parser_t* parser , void* buffer , size_t len , int* off ) {
    char buf[4];
    int offset = _proto_parser_peek_buffer(parser,buf,4,buffer,len);
    if( offset < 0 ) {
        if( _proto_parser_cache_buffer(parser,buffer,len) != 0 ) {
            return PROTO_ERR_UNKNOWN_TYPE;
        } else {
            return 1;
        }
    } else {
        if(  buf[0] == 'G' ) {
            if( buf[1] == 'E' && buf[2] == 'T' ) {
                parser->type = PROTO_GET;
            } else {
                return PROTO_ERR_UNKNOWN_TYPE;
            }
        } else if ( buf[0] == 'P' ) {
            if( buf[1] == 'U' && buf[2] == 'T' ) {
                parser->type = PROTO_PUT;
            } else {
                return PROTO_ERR_UNKNOWN_TYPE;
            }
        } else if( buf[3] != ' ' ) {
            return PROTO_ERR_UNKNOWN_TYPE;
        }
    }
    parser->state = PROTO_REQUEST_VERSION;
    _proto_parser_commit_buffer(parser,4);
    *off = offset;
    return 0;
}

int _proto_request_parse_version( struct proto_parser_t* parser , void* buffer , size_t len , int* off ) {
    // Version. We have a extra space and version number.
    // The longest version number should be 3 at most which
    // is 9.9
    char buf[4];
    int offset = _proto_parser_peek_buffer(parser,buf,4,buffer,len);
    if( offset < 0 ) {
        if( _proto_parser_cache_buffer(parser,buffer,len) != 0  ) {
            return PROTO_ERR_UNKNOWN_VERSION;
        } else {
            return 1;
        }
    } else {
        if( buf[1] != '.' || buf[3] != ' ' ) {
            return PROTO_ERR_UNKNOWN_VERSION;
        }
        parser->major_version = buf[0]-'0';
        parser->minor_version = buf[2]-'0';
        if( parser->major_version != MAJOR_VERSION || parser->minor_version != MINOR_VERSION )
            return PROTO_ERR_UNKNOWN_VERSION;
    }
    parser->state = PROTO_REQUEST_OPTION;
    _proto_parser_commit_buffer(parser,4);
    *off = offset;
    return 0;
}

int _proto_request_parse_len( struct proto_parser_t* parser , void* buffer , size_t len , int* off ) {
    // The largest data chunk we can receive is 1MB
    // which is 1024*1024 , so at most it has 7 digits
    // plus an extra space, it has 8 digits.
    char buf[8];
    size_t str_len;
    int offset;
    assert( parser->state != PROTO_GET );
    offset = _proto_parser_peek_buffer_until(parser,buf,8,' ',buffer,len,&str_len);
    if( offset < 0 ) {
        if( str_len == 8 ) {
            return PROTO_ERR_TOO_LARGE_DATA;
        } else {
            if( _proto_parser_cache_buffer(parser,buffer,len) != 0 ) {
                return PROTO_ERR_TOO_LARGE_DATALEN;
            } else {
                return 1;
            }
        }
    } else {
        buf[str_len-1]=0;
        errno = 0;
        parser->data_len = (int)strtoul(buf,NULL,10);
        if( errno != 0 )
            return PROTO_ERR_UNKNOWN_DATALEN;
        else if( parser->data_len > MAX_DATA_LEN )
            return PROTO_ERR_TOO_LARGE_DATALEN;
    }
    parser->state = PROTO_REQUEST_NAME;
    _proto_parser_commit_buffer(parser,str_len);
    *off = offset;
    return 0;
}

int _proto_request_parse_name( struct proto_parser_t* parser , void* buffer , size_t len , int* off ) {
    char buf[128];
    size_t str_len;
    int offset;
    offset = _proto_parser_peek_buffer_until(parser,buf,MAX_NAME_LEN+3,'\n',buffer,len,&str_len);
    if( offset < 0  ) {
        if( str_len == 128 ) {
            return PROTO_ERR_TOO_LONG_NAME;
        } else {
            if( _proto_parser_cache_buffer(parser,buffer,len) != 0 ){
                return PROTO_ERR_PROTOCOL_UNRECOGNIZE;
            } else {
                return 1;
            }
        }
    }
    if( buf[str_len-2] != '\r' || buf[str_len-1] != '\n' ) {
        return PROTO_ERR_PROTOCOL_UNRECOGNIZE;
    }
    // Change it to space
    buf[str_len-2] = 0;
    parser->name = strdup(buf);
    VERIFY(parser->name);
    if( parser->data_len == 0 || parser->type == PROTO_GET ) {
        parser->state = PROTO_DONE;
        parser->data = NULL;
    } else {
        parser->state = PROTO_REQUEST_DATA;
    }
    _proto_parser_commit_buffer(parser,str_len);
    *off = offset;
    return 0;
}

int _proto_request_parse_data( struct proto_parser_t* parser , void* buffer , size_t len ) {
    size_t left_buffer_len = len + parser->cache_size;
    if( left_buffer_len + parser->data_size > parser->data_len )
        return PROTO_ERR_TOO_LARGE_DATA;
    else {
        if( parser->data_size == 0 ) {
            assert(parser->data == NULL);
            parser->data = malloc( parser->data_len );
            VERIFY(parser->data);
        }
        if( parser->cache_size != 0 ) {
            memcpy( ((char*)(parser->data))+parser->data_size, parser->cache, parser->cache_size);
            parser->data_size += parser->cache_size;
            parser->cache_size =0;
        }
        memcpy(((char*)(parser->data))+parser->data_size,buffer,len);
        parser->data_size += len;
        if( parser->data_size == parser->data_len ) {
            parser->state = PROTO_DONE;
            return 0;
        }
        return 1;
    }
}

const char* strchar2( const char* str , const char* delimiter ) {
    int i;
    for( i=0 ; str[i] ; ++i ) {
        if( strchr(delimiter,str[i] ) != NULL )
            return str+i;
    }
    return NULL;
}

int _proto_request_parse_option_comb( struct proto_parser_t* parser , char* buffer , int str_len , const char* delimiter ) {
    const char* limits_str;
    const char* timeout_str;
    int off = delimiter-buffer;
    if( *delimiter == '|' ) {
        parser->option_type = PROTO_OPTION_TIMEOUT_OR_LIMITS;
    } else {
        parser->option_type = PROTO_OPTION_TIMEOUT_AND_LIMITS;
    }
    if( buffer[off+1] == 'T' ) {
        if( buffer[0] == 'L' ) {
            limits_str = buffer+1;
            buffer[off]= 0;
            timeout_str = buffer+off+2;
            buffer[str_len]= 0;
        } else {
            return PROTO_ERR_UNKNOWN_OPTION;
        }
    } else if ( buffer[off+1] == 'L' ) {
        if( buffer[0] == 'T' ) {
            limits_str = buffer+off+2;
            timeout_str = buffer+1;
            buffer[off] = 0;
            buffer[str_len] = 0;
        } else {
            return PROTO_ERR_UNKNOWN_OPTION;
        }
    } else {
        return PROTO_ERR_UNKNOWN_OPTION;
    }
    errno = 0;
    parser->timeout = (int)strtol(timeout_str,NULL,10);
    parser->limits = (int)strtoul(limits_str,NULL,10);
    if( errno != 0 )
        return PROTO_ERR_UNKNOWN_OPTION;
    else if( parser->type == PROTO_GET ||
             parser->type == PROTO_PUT ) {
        // For these 2 types, we don't allow the negative timer value
        if(parser->timeout <0) {
            return PROTO_ERR_UNKNOWN_OPTION;
        }
    }
    return 0;
}

int _proto_request_parse_option( struct proto_parser_t* parser , void* buffer , size_t len , int* off ) {
    // Largest number for 32 bits integer will have 10 digits. So at most we need
    // L10|R10 --> 10 + 10 + 1 + 1 + 1 = 23 and a extra space
    char buf[24];
    size_t str_len;
    int offset = _proto_parser_peek_buffer_until(parser,buf,24,' ',buffer,len,&str_len);
    if( offset < 0 ) {
        if( str_len == 24 ) {
            return PROTO_ERR_TOO_LARGE_OPTION;
        } else {
            if( _proto_parser_cache_buffer(parser,buffer,len) != 0 ) {
                return PROTO_ERR_PROTOCOL_UNRECOGNIZE;
            } else {
                return 1;
            }
        }
    } else {
        // Parsing the option combinations
        if( buf[0] == 'L' && parser->type != PROTO_GET ) {
           const char* delimiter = strchar2(buf+1,"|&");
           if( delimiter == NULL ) {
               // It means we must only have one limits here
               parser->option_type = PROTO_OPTION_LIMITS;
               buf[str_len-1] =0;
               errno = 0;
               parser->limits = atoi(buf+1);
               if( errno != 0 )
                   return PROTO_ERR_UNKNOWN_OPTION;
           } else {
               int ret = _proto_request_parse_option_comb(parser,buf,str_len,delimiter);
               if( ret < 0 )
                   return ret;
           }
        } else if ( buf[0] == 'T' ) {
            const char* delimiter = strchar2(buf+1,"|&");
            if( delimiter == NULL ) {
                parser->option_type = PROTO_OPTION_TIMEOUT;
                buf[str_len-1] =0;
                errno = 0;
                parser->timeout = atoi(buf+1);
                if( errno != 0 )
                    return PROTO_ERR_UNKNOWN_OPTION;
            } else {
                int ret;
                if( parser->type == PROTO_GET ) {
                    return PROTO_ERR_UNKNOWN_OPTION;
                }
                ret = _proto_request_parse_option_comb(parser,buf,str_len,delimiter);
                if( ret < 0 )
                    return ret;
            }
        } else {
            return PROTO_ERR_UNKNOWN_OPTION;
        }
    }
    *off = offset;
    parser->state = PROTO_REQUEST_LEN;
    _proto_parser_commit_buffer(parser,str_len);
    return 0;
}

#define SHIFT_BUFFER(b,l,o) \
    do { \
        char* cbuf = (char*)b; \
        b = cbuf + o; \
        l -=o ; \
        if( l == 0 ) \
            return parser->state == PROTO_DONE ? 0 : 1; \
    } while(0)

int proto_request_parse( struct proto_parser_t* parser , void* buffer , size_t len ) {
    int offset;
    int ret;
    do {
        switch( parser->state ) {
        case PROTO_REQUEST_TYPE:
            ret = _proto_request_parse_type(parser,buffer,len,&offset);
            if( ret < 0 )
                return ret;
            else if( ret == 1 ) {
                return 1;
            } else {
                SHIFT_BUFFER(buffer,len,offset);
            }
            break;
        case PROTO_REQUEST_VERSION:
            // Version. We have a extra space and version number.
            // The longest version number should be 3 at most which
            // is 9.9
            ret = _proto_request_parse_version(parser,buffer,len,&offset);
            if( ret < 0 )
                return ret;
            else if( ret == 1 ) {
                return 1;
            } else {
                SHIFT_BUFFER(buffer,len,offset);
            }
            break;
        case PROTO_REQUEST_LEN:
            // The largest data chunk we can receive is 1MB
            // which is 1024*1024 , so at most it has 7 digits
            // plus an extra space, it has 8 digits.
            ret = _proto_request_parse_len(parser,buffer,len,&offset);
            if( ret < 0 )
                return ret;
            else if( ret == 1 ) {
                return 1;
            } else {
                SHIFT_BUFFER(buffer,len,offset);
            }
            break;
        case PROTO_REQUEST_NAME:
            ret = _proto_request_parse_name(parser,buffer,len,&offset);
            if( ret < 0 )
                return ret;
            else if( ret == 1 ) {
                return 1;
            } else {
                SHIFT_BUFFER(buffer,len,offset);
            }
            break;
        case PROTO_REQUEST_DATA:
            return _proto_request_parse_data(parser,buffer,len);
        case PROTO_REQUEST_OPTION:
            ret = _proto_request_parse_option(parser,buffer,len,&offset);
            if( ret < 0 )
                return ret;
            else if( ret == 1 ) {
                return 1;
            } else {
                SHIFT_BUFFER(buffer,len,offset);
            }
            break;
        default: assert(0); return -1;
        }
    } while( 1 );
}

void proto_parser_clear( struct proto_parser_t* parser ) {
    if( parser->name )
        free((void*)parser->name);
    if( parser->data )
        free(parser->data);
}

#undef SHIFT_BUFFER


// Network part

static struct msg_table_t MSG_TABLE; // Our global message table
struct net_server_t SERVER; // Net server

#define CONNECTION_TIMEOUT 30000 // 30 seconds

struct msg_get_t {
    int timeout;
    int freq;
    const char* name;
};

struct msg_put_t {
    int limits;
    int option_type;
    struct net_connection_t* conn;
    void* data;
    size_t data_len;
};

void _msg_get_clear( struct msg_get_t* msg ) {
    free((void*)msg->name);
    free(msg);
}

void _msg_put_clear( struct msg_put_t* msg ) {
    free(msg->data);
    free(msg);
}

void _net_msg_handle_query( struct msg_put_t* put_msg , const char* name ) {
    void* data;
    if( put_msg->option_type != PROTO_OPTION_TIMEOUT ) {
        --(put_msg->limits);
        switch( put_msg->option_type ) {
        case PROTO_OPTION_LIMITS:
        case PROTO_OPTION_TIMEOUT_OR_LIMITS:
            if( put_msg->limits == 0 ) {
                if( put_msg->conn != NULL ) {
                    net_cancel(put_msg->conn);
                    put_msg->conn = NULL;
                }
                goto free_resource;
            }
            return;
        case PROTO_OPTION_TIMEOUT_AND_LIMITS:
            if( put_msg->limits == 0 && put_msg->conn == NULL )
                goto free_resource;
            return;
        default: assert(0); return;
        }
free_resource:
        VERIFY(msg_table_remove(&MSG_TABLE,name,&data) ==0);
        assert( data == put_msg );
        _msg_put_clear(put_msg);
    }
}

int net_handler_get_callback( int ev , int ec , struct net_connection_t* conn ) {
    if( ec != 0 ) {
        free(conn->user_data);
        return NET_EV_CLOSE;
    } else {
        if( ev & NET_EV_TIMEOUT ) {
            struct msg_get_t* get_msg = (struct msg_get_t*)conn->user_data;
            struct msg_t* m = msg_table_query( &MSG_TABLE , get_msg->name );
            if( m != NULL ) {
                // Format the reply now and send it back to our user
                char header[128];
                struct msg_put_t* put_msg = (struct msg_put_t*)(m->data);
                int header_sz = sprintf(header,"REP %d.%d OK %u\r\n",MAJOR_VERSION,MINOR_VERSION,put_msg->data_len);
                // Write to the buffer now
                net_buffer_produce(&(conn->out),header,(size_t)header_sz);
                if( put_msg->data_len !=0 )
                    net_buffer_produce(&(conn->out),put_msg->data,put_msg->data_len);
                _net_msg_handle_query(put_msg,get_msg->name);
                _msg_get_clear(get_msg);
                conn->timeout = CONNECTION_TIMEOUT;
                return NET_EV_LINGER_SILENT|NET_EV_TIMEOUT;
            }
            --get_msg->freq;
            if( get_msg->freq == 0 ) {
                char header[128];
                int header_sz = sprintf(header,"REP %d.%d FAIL 7\r\nTimeout",MAJOR_VERSION,MINOR_VERSION);
                net_buffer_produce(&(conn->out),header,(size_t)header_sz);
                free(get_msg);
                conn->timeout = CONNECTION_TIMEOUT;
                return NET_EV_LINGER_SILENT|NET_EV_TIMEOUT;
            }
            conn->timeout = get_msg->timeout;
            return NET_EV_TIMEOUT;
        } else {
            return NET_EV_CLOSE;
        }
    }
}

int net_handler_put_callback( int ev , int ec , struct net_connection_t* conn ) {
    void* data;
    if( ev & NET_EV_TIMEOUT ) {
        const char* name = (const char*)(conn->user_data);
        struct msg_t* m = msg_table_query(&MSG_TABLE,name);
        struct msg_put_t* put_msg;
        assert( m != NULL );
        put_msg = (struct msg_put_t*)m->data;
        put_msg->conn = NULL;
        switch( put_msg->option_type ) {
        case PROTO_OPTION_TIMEOUT:
        case PROTO_OPTION_TIMEOUT_OR_LIMITS:
            goto delete_resource;
        case PROTO_OPTION_TIMEOUT_AND_LIMITS:
            if( put_msg->limits == 0 ) {
                goto delete_resource;
            } else {
                return NET_EV_CLOSE;
            }
            return NET_EV_TIMEOUT;
        default: assert(0); return NET_EV_TIMEOUT;
        }
delete_resource:
        msg_table_remove(&MSG_TABLE,name,&data);
        free(conn->user_data);
        _msg_put_clear(put_msg);
        return NET_EV_CLOSE;
    }
    return NET_EV_CLOSE;
}

int net_handle_request( struct proto_parser_t* parser , struct net_connection_t* conn ) {
    if( parser->type == PROTO_GET ) {
        // Try to get the data from the cache directly now
        struct msg_t* m = msg_table_query(&MSG_TABLE,parser->name);
        if( m == NULL ) {
            // We are not lucky here, no message is found, so we need to make
            // our client wait for the time it signals for us
            struct msg_get_t* msg = malloc(sizeof(struct msg_get_t));
            VERIFY(msg != NULL);
            msg->freq = 10;
            msg->timeout = parser->timeout/msg->freq;

            msg->name = parser->name;
            parser->name = NULL;
            conn->user_data = msg;
            conn->timeout = msg->timeout;
            conn->cb = net_handler_get_callback;
            return NET_EV_TIMEOUT;
        } else {
            struct msg_put_t*  put_msg = (struct msg_put_t*)(m->data);
            char header[128];
            int header_sz = sprintf(header,"REP %d.%u OK %u\r\n",MAJOR_VERSION,MINOR_VERSION,put_msg->data_len);
            assert( strcmp(m->name,parser->name) == 0 );
            net_buffer_produce(&(conn->out),header,(size_t)header_sz);
            if( put_msg->data_len !=0 ) {
                assert(put_msg->data != NULL);
                net_buffer_produce(&(conn->out),put_msg->data,put_msg->data_len);
            }
            _net_msg_handle_query(put_msg,parser->name);
            return NET_EV_WRITE;
        }
    } else {
        char header[128];
        int header_sz;
        struct msg_put_t* put_msg = malloc( sizeof( struct msg_put_t ) );
        VERIFY(put_msg != NULL);
        put_msg->data = parser->data;
        put_msg->data_len = parser->data_len;
        put_msg->limits = parser->limits;
        put_msg->option_type = parser->option_type;
        put_msg->conn = NULL;

        if( msg_table_insert(&MSG_TABLE,put_msg,parser->name) != 0 ) {
            free(put_msg);
            header_sz = sprintf(header,"REP %d.%d FAIL 12\r\nName existed",MAJOR_VERSION,MINOR_VERSION);
            net_buffer_produce(&(conn->out),header,(size_t)header_sz);
            return NET_EV_LINGER_SILENT;
        }
        // For a limit bound, no timer is added here
        if( parser->option_type != PROTO_OPTION_LIMITS )
            put_msg->conn = net_timer(&SERVER,net_handler_put_callback,(void*)parser->name,parser->timeout);

        parser->name = NULL;
        parser->data = NULL;
        parser->data_len =0;

        header_sz = sprintf(header,"REP %d.%d OK 0\r\n",MAJOR_VERSION,MINOR_VERSION);
        net_buffer_produce(&(conn->out),header,(size_t)header_sz);
        conn->timeout = CONNECTION_TIMEOUT;
        return NET_EV_LINGER_SILENT|NET_EV_TIMEOUT;
    }
}

// This handler is used as the first phase for reading the protocol. Once the protocol
// is ready and parsing finished, we will turn the internal state to the next stage based
// on the user's protocol type.
int net_msg_proto_read_handler( int ev , int ec , struct net_connection_t* conn ) {
    struct proto_parser_t* parser = (struct proto_parser_t*)(conn->user_data);
    // Get the data out of the buffer now and parse it
    if( ec != 0 || ((ev & NET_EV_EOF) && parser->state != PROTO_DONE) ) {
        proto_parser_clear(parser);
        free(parser);
        return NET_EV_CLOSE;
    } else {
        if( ev & NET_EV_READ ) {
            size_t buf_sz = net_buffer_readable_size(&(conn->in));
            void* buf = net_buffer_consume(&(conn->in),&buf_sz);
            int ret = proto_request_parse(parser,buf,buf_sz);
            struct sockaddr_in peer_addr;
            socklen_t sz = sizeof(peer_addr);
            if( ret < 0 ) {
                // We have an error , just handle it at once
                char buf[256];
                const char* err_desc = proto_error(ret);
                int bsz = sprintf(buf,"REP %d.%d FAIL %u\r\n%s",MAJOR_VERSION,MINOR_VERSION,
                    strlen(err_desc),err_desc);
                assert(bsz >0);
                net_buffer_produce(&(conn->out),buf,(size_t)bsz);
                // Free the parser resource
                proto_parser_clear(parser);
                free(parser);
                // Log this rare situation
                if(getpeername(conn->socket_fd,(struct sockaddr*)&peer_addr,&sz) ==0) {
                    msg_log(LOG_WARN,
                        "The peer:%s:%d has sent us a incorrect protocol!",
                        inet_ntoa(peer_addr.sin_addr),(int)ntohs(peer_addr.sin_port));
                }
                conn->timeout = CONNECTION_TIMEOUT;
                return NET_EV_LINGER_SILENT|NET_EV_TIMEOUT;
            } else if( ret == 0 ) {
                int ev = net_handle_request(parser,conn);
                // Here we don't call proto_parser_clear since in the net_handle_request function
                // all the member data will be transferred into its owner structure, so just free
                // the parser is enough for us .
                free(parser);
                return ev;
            } else {
                return NET_EV_READ;
            }
        } else {
            return NET_EV_CLOSE;
        }
    }
}

int net_msg_accept( int err_code , struct net_server_t* ser, struct net_connection_t* connection ) {
    if( err_code == 0 ) {
        struct proto_parser_t* p = malloc( sizeof(struct proto_parser_t) );
        proto_parser_init(p);
        connection->cb = net_msg_proto_read_handler;
        connection->user_data = p;
        return NET_EV_READ;
    } else {
        return NET_EV_CLOSE;
    }
}

// This function will leak memory but after calling this function our process is done
const char* get_fatal_error_str() {
#ifdef _WIN32
    LPSTR s = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        s, 0, NULL);
    return s;
#else
    return strerror(errno);
#endif // _WIN32
}

void tinymq_stop( int val ) {
    // The only thread safe function for our network library
    net_server_wakeup(&SERVER);
}

#ifdef _WIN32
BOOL WINAPI tinymq_stop_win32( DWORD val ) {
    tinymq_stop(0);
    return TRUE;
}
#endif // _WIN32

void install_term_handler() {
#ifdef _WIN32
    SetConsoleCtrlHandler(tinymq_stop_win32,TRUE);
#else
    signal(SIGTERM,tinymq_stop);
    signal(SIGINT,tinymq_stop);
    signal(SIGTSTP,tinymq_stop);
#endif
}

int tinymq_start( const char* addr , const char* log_option ) {
    int wakeup;
    install_term_handler();
    // initialize the MSG_TABLE
    msg_table_init(&MSG_TABLE);
    // parsing the log option
    if( log_option != NULL ) {
        if( strcmp(log_option,"of") == 0 || strcmp(log_option,"fo") == 0 ) {
            LOG_OPTION = LOG_STDOUT_AND_FILE;
        } else if( strcmp(log_option,"f") == 0 ) {
            LOG_OPTION = LOG_FILE;
        } else if( strcmp(log_option,"o") == 0 ) {
            LOG_OPTION = LOG_STDOUT;
        }
    }
    // create the server
    if( net_server_create(&SERVER,addr,net_msg_accept) != 0 )
        return -1;
    msg_log(LOG_INFO,"%s\n","The tinymq server starts!");
    for( ;; ) {
        if( net_server_poll(&SERVER,-1,&wakeup) <0 ) {
            msg_log(LOG_ERROR,"A fatal error:%s has happened,the server aborts!",
                get_fatal_error_str());
            return -1;
        } else if( wakeup ) {
            net_server_destroy(&SERVER);
            msg_log(LOG_INFO,"%s","The server stops!");
            return 0;
        }
    }
    return 0;
}

#ifdef __cplusplus
}
#endif // __cplusplus
