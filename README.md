#TinyMQ
TinyMQ is an extremely tiny and simple in memory message queue. It contains absolute minimum functionality that
makes some obvious but simple usage easy to work.You could use it sink your log information from other process or 
collect some external message for your requirements. It uses another library I created called tiny network.
##How it works
TinyMQ just sits and wait for any TCP connection for a specific ipv4 address and port. And it recognize an extremely
simple text based protocol to work. That's it. 
Compile it and run it like: tinymq --addr 127.0.0.1 --port 12345 --log-option of, then it starts to run.

##OK, how can I use it
Sorry, TinyMQ doesn't comes with any library serves as a protocol reader/writer or parser/serializer. Because it wants
the user to know the detail of protocol and implement their own library. The protocol is really simple, that even you
get the library and set up the environment would be more expensive than just write one. 

For protocol serializer ,you can write it like this:
```
void* serialize_request( const char* req_name , const char* option , const char* key , const char* data , size_t data_sz ) {
	char header[128];
	int header_sz = sprintf(header,"%s 1.0 %s %u %s\r\n",req_name,option,data_sz,key);
	char* req = malloc(data_sz+header_sz);
	memcpy(req,header,header_sz);
	memcpy(req+header_sz,data,data_sz);
	return req;
}
```
Don't forget to free the returned memory. Easy ? What about parser ?
```
void* parse_request( void* rep ,  size_t rep_len , char* reply_status , size_t* data_sz ) {
	int i ;
	// Do not use strchr unless you are sure rep is a null terminated string
	for( i = 0 ; i < rep_len ; ++i ) {
		if(((char*)rep)[i] == '\r' && (i+1 <rep_len && ((char*)rep)[i+1] =='\n'))
			break;
		else
			return NULL;
	}
	((char*)(rep))[i]=0;
	sscanf(rep,"REP 1.0 %s %d",reply_status,data_sz);
	return rep+i+2;
}
```
##Detail of Protocol
Protocol is a request/reply protocol and transfer using TCP.
 
###Request
The request has 2 method currently, one is PUT , the other is GET. For request structure, it looks like this:
[MethodName][Space][Version][Space][Option][Space][DataLen][Space][Name]\r\n[Data]
So a typical PUT request is like this:
PUT 1.0 L10000 1024 Key1\r\n...
For get is same same thing, only changes your PUT to GET and also get doesn't have any data appending, so 1024 changes
to 0.

The only notes for protocol is the OPTION area. You could specify the duration for message in time or visit times fashion.
For time, you specify the milliseconds this message could live;for visit times, you specify how many times you wish this 
message to be GET. And you could also use combination operator to define combination of these two elements. 
Example:

1. L1000 : visit 1000 times and then delete it
2. T10000: after 10 seconds and then delete it
3. L1000|T10000: delete it after 10 seconds or 1000 times visit, whichever comes first
4. L1000&T10000: 10 seconds and 1000 times visit both satisfy and then delete it

###Reply
For the reply, it is very simple:
REP 1.0 FAIL/OK [DATA-LENGTH]\r\n--data--

##Command line tool
A simple command line tool is provided for doing this message exchange.

##Build
1. Make
2. Visual Studio
3. Code Blocks

##Platform
1. Linux
2. Windows

##Dependency
Tiny network, but the source code is included. So no dependency.

##License
The code is in PUBLIC DOMAIN.










