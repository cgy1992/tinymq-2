#include "tinymq.c"

#include <network.h>
#include <assert.h>
#include <stdio.h>

// Testing code for sys-msg-deamon function

// Message Table Function
void msg_table_utest() {
    int i;
    int* iarray ;
    struct msg_table_t msg_table;
    char name[12];
    // Initialize the message table
    msg_table_init(&msg_table);
    assert(msg_table.size == 0 );
    assert(msg_table.cap == INIT_MSGTABLE_LEN);
    assert(msg_table.buckets != NULL);
    // Insert some data
    iarray = malloc(sizeof(int)*128);
    for( i = 0 ; i < 128 ; ++i ) {
        iarray[i] = i;
        sprintf(name,"%d",i);
        assert( msg_table_insert(&msg_table,iarray+i,name) == 0 );
        assert( msg_table.size == i+1 );
    }
    // Search some data
    for( i = 0 ; i < 128 ; ++i ) {
        struct msg_t* m;
        sprintf(name,"%d",i);
        m = msg_table_query(&msg_table,name);
        assert( m != NULL );
        assert( *((int*)(m->data)) == i );
    }
    // Remove some data
    for( i = 0 ; i < 128 ; ++i ) {
        void* data;
        sprintf(name,"%d",i);
        assert( msg_table_remove(&msg_table,name,&data) == 0 );
        assert( msg_table.size == 127-i );
    }
    
    for( i = 0 ; i < 128 ; ++i ) {
        struct msg_t* m;
        sprintf(name,"%d",i);
        m = msg_table_query(&msg_table,name);
        assert( m == NULL );
    }
    assert( msg_table.size == 0 );
    printf("Message table test done!\n");
}

void proto_parser_utest() {
    struct proto_parser_t p;
    int ret;
    const char* data = "ABCDEFGHIJ";
    const char* proto1 = "PUT 1.0 T100|L100 10 Name1\r\n" \
        "ABCDEFGHIJ";

    const char* proto2 = "PUT 1.0 L9987 10 NameSomeBody\r\n" \
        "ABCDEFGHIJ";

    proto_parser_init(&p);

    // Parsing the proto1 
    ret = proto_request_parse(&p,(void*)proto1,strlen(proto1));
    assert( ret == 0 );
    assert( p.limits == 100 );
    assert( p.timeout == 100 );
    assert( strcmp(p.name,"Name1") == 0 );
    assert( p.option_type == PROTO_OPTION_TIMEOUT_OR_LIMITS );
    assert( p.major_version == 1 );
    assert( p.minor_version == 0 );
    assert( p.type == PROTO_PUT );
    assert( p.data_len == 10 );
    assert( memcmp(p.data,data,strlen(data)) == 0 );

    // Parsing the proto2
    proto_parser_init(&p);
    ret = proto_request_parse(&p,(void*)proto2,strlen(proto2));
    assert( ret == 0 );
    assert( p.limits == 9987 );
    assert( strcmp(p.name,"NameSomeBody") == 0 );
    assert( p.option_type == PROTO_OPTION_LIMITS );
    assert( p.major_version == 1 );
    assert( p.minor_version == 0 );
    assert( p.type == PROTO_PUT );
    assert( p.data_len == 10 );
    assert( memcmp(p.data,data,strlen(data)) == 0 );
}

void proto_parser_partial_utest() {
    struct proto_parser_t p;
    int i;
    const char* data = "ABCDEFGHIJ";
    const char* proto1 = "PUT 1.0 T100|L100 10 Name1\r\n" \
        "ABCDEFGHIJ";

    const char* proto2 = "PUT 1.0 L9987 10 NameSomeBody\r\n" \
        "ABCDEFGHIJ";
    proto_parser_init(&p);
    i = 0;
    while( 1 ) {
        void* ptr = ((char*)proto2) + i;
        int ret = proto_request_parse(&p,ptr,1);
        ++i;
        if( ret == 0 )
            break;
        assert( ret == 1 );
    }
    assert( p.limits == 9987 );
    assert( strcmp(p.name,"NameSomeBody") == 0 );
    assert( p.option_type == PROTO_OPTION_LIMITS );
    assert( p.major_version == 1 );
    assert( p.minor_version == 0 );
    assert( p.type == PROTO_PUT );
    assert( p.data_len == 10 );
    assert( memcmp(p.data,data,strlen(data)) == 0 );
    printf("Proto partial parser test done!\n");
}

// Pressure test
static const char* CH_TABLE =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

const char* rand_str( int min , int max , int* sz ) {
    int len;
    double ratio;
    int i = 0 ;
    char* ret ;
    const int table_len = strlen(CH_TABLE)-1;
    assert( min <= max );
    len = rand();
    ratio = (double)(len)/RAND_MAX;
    len = (int)(ratio * (max-min) + min);
    ret = malloc(len+1);
    for( i = 0 ; i < len ; ++i ) {
        min = rand();
        min = (int)(((double)(len)/RAND_MAX)*table_len);
        ret[i] = CH_TABLE[min];
    }
    ret[len] = 0;
    if( sz != NULL )
        *sz = len;
    return ret;
}

#define MAX_CONNECTION 500

#define MAX_LIMITS 5
#define MIN_LIMITS 1

#define MIN_KEYLEN 2
#define MAX_KEYLEN 63

#define MIN_DATALEN 1024
#define MAX_DATALEN 1024*1024

#define SCHEDULE_TIME 500 // 500 ms for scheduling time

// We don't use timeout since it is not very deterministic and also not very accurate

struct case_t {
    const char* key;
    const char* data;
    int data_len;
    int get_times;
    int try_times;
    int allowed_times;
    struct case_t* next;
    struct case_t* prev;
};

struct case_t TEST_CASE;
size_t TEST_SIZE;
struct net_server_t SERVER;
static const char* ADDRESS="127.0.0.1:12345";

#define INSERT_CASE(x) \
    do { \
        TEST_CASE.prev->next = x; \
        x->prev = TEST_CASE.prev; \
        x->next = &TEST_CASE; \
        TEST_CASE.prev = x; \
        ++TEST_SIZE; \
    } while(0)

#define REMOVE_CASE(x) \
    do { \
        x->prev->next = x->next; \
        x->next->prev = x->prev; \
        --TEST_SIZE; \
    } while(0)

#define INIT_CASE() \
    do { \
        TEST_CASE.next=&TEST_CASE; \
        TEST_CASE.prev=&TEST_CASE; \
    } while(0)

struct case_t* gen_put() {
    int val;
    if( TEST_SIZE == MAX_CONNECTION ) {
        return 0;
    } else {
        // generate a new test case
        struct case_t* new_case = malloc(sizeof(struct case_t));
        val = rand();
        new_case->allowed_times = (int)(((double)val/RAND_MAX)*(MAX_LIMITS-MIN_LIMITS) + MIN_LIMITS);
        new_case->get_times = 0;
        new_case->try_times = 0;
        val = rand();
        val = (int)(((double)val/RAND_MAX)*(MAX_KEYLEN-MIN_KEYLEN) + MIN_KEYLEN);
        new_case->key = rand_str(MIN_KEYLEN,val,NULL);
        val = (int)(((double)val/RAND_MAX)*(MAX_DATALEN-MIN_DATALEN) + MIN_DATALEN);
        new_case->data= rand_str(MIN_DATALEN,val,&(new_case->data_len));
        INSERT_CASE(new_case);
        return new_case;
    }
}

int req_put( int ev , int ec , struct net_connection_t* conn ) {
    if( ec != 0 )
        return NET_EV_CLOSE;
    if( ev & NET_EV_CONNECT ) {
        struct case_t* new_case = gen_put();
        char header[128];
        int sz = sprintf(header,"PUT 1.0 L%d %d %s\r\n",new_case->allowed_times,new_case->data_len,new_case->key);
        net_buffer_produce(&(conn->out),header,sz);
        net_buffer_produce(&(conn->out),new_case->data,new_case->data_len);
        return NET_EV_LINGER_SILENT;
    }
    return NET_EV_CLOSE;
}

char* get_data( void* data , size_t len , int* sz ) {
    // find out the /r/n and return the rest of the data
    size_t i;
    for( i = 0 ; i < len ; ++i ) {
        if( ((char*)(data))[i] == '\r' ) {
            if( i+1 != len && ((char*)(data))[i+1] == '\n') {
                break;
            }
        }
    }
    if( i == len )
        return NULL;
    *sz = len - (i+2);
    return ((char*)(data) + (i+2));
}


struct case_t* del_case( struct case_t* c ) {
    struct case_t* n = c->prev;
    free((void*)c->data);
    free((void*)c->key);
    REMOVE_CASE(c);
    free(c);
    return n;
}

int req_get( int ev , int ec , struct net_connection_t* conn ) {
    struct case_t* c = (struct case_t*)(conn->user_data);
    if( ec != 0 || c == NULL )
        return NET_EV_CLOSE;
    if( ev & NET_EV_CONNECT ) {
        char header[128];
        int sz;
        // sending the get request
        sz = sprintf(header,"GET 1.0 T1000 0 %s\r\n",c->key);
         net_buffer_produce(&(conn->out),header,sz);
        return NET_EV_WRITE;
    } else if( ev & NET_EV_WRITE ) {
        // We need to wait for the reading operation
        return NET_EV_READ;
    } else if( ev & NET_EV_READ ) {
        return NET_EV_READ;
    } else if ( ev & NET_EV_EOF ) {
        void* data;
        size_t data_len = net_buffer_readable_size(&(conn->in));
        char* send_data;
        int send_data_len;
        data = net_buffer_consume(&(conn->in),&data_len);
        send_data = get_data(data,data_len,&send_data_len);
        if( send_data == NULL || (c->data_len != send_data_len || memcmp(send_data,c->data,send_data_len) != 0) ) {
            printf("Failed:%s\n",c->key);
        } else {
            printf("Pass:%s\n",c->key);
        }
        ++c->get_times;
        if( c->get_times == c->allowed_times ) {
            del_case(c);
        }
        return NET_EV_CLOSE;
    } else {
        return NET_EV_CLOSE;
    }
}

int timer_cb( int ev , int ec , struct net_connection_t* conn ) {
    int i = TEST_SIZE;
    int gen_num = 0;
    struct case_t* c;
    struct case_t* pc;
    // Generate PUT 
    for( ; i < MAX_CONNECTION ; ++i ) {
        // Connect to the remove server asynchronously 
        net_non_block_client_connect(&SERVER,ADDRESS,req_put,NULL,1000);
        ++gen_num;
        if( gen_num == 10 )
            break;
    }
    // Generate GET
    c = TEST_CASE.next;
    for( ; c != &TEST_CASE ; c = pc ) {
        pc = c->next;
        if(c->try_times < c->allowed_times) {
            ++c->try_times;
            net_non_block_client_connect(&SERVER,ADDRESS,req_get,c,1000);
        }
    }
    conn->timeout = SCHEDULE_TIME;
    return NET_EV_TIMEOUT;
}

void pressure_test() {
    srand(0);
    INIT_CASE();
    net_init();
    net_server_create(&SERVER,NULL,NULL);
    net_timer(&SERVER,timer_cb,NULL,SCHEDULE_TIME);
    for(;;) {
        net_server_poll(&SERVER,-1);
    }
}

int main() {
    pressure_test();
    getchar();
}