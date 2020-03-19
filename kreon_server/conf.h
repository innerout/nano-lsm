#ifndef __TUCANAS_CONVF_H_
#define __TUCANAS_CONVF_H_

#include <inttypes.h>
#include <semaphore.h>

/*mvard added defines for return when function succeded or failed*/
#define KREON_SUCCESS 1
#define KREON_FAILURE 0
#define KREON_KEY_NOT_FOUND 2

/*gesalous, priorities and properties regarding the conections*/
#define HIGH_PRIORITY 1203
#define LOW_PRIORITY 9829
/*connection properties for memory sizes of the connections*/
#define DEFAULT_MEMORY_SIZE_OPTION 0xFA
#define CONTROL_CONNECTION_MEMORY_SIZE 1048576

//#if REGULAR_FAKE 0
#define TUCANA_DEBUG 0
#define MAX_MAILBOX 1
#define MAX_MAILBOX_LESS_1 (MAX_MAILBOX - 1)
#define CLI_SIGNAL 0	// 1 we are using pthread_kill to wake threads, 0 we are using pthread_cond_broadcast

#define MRQ_SIZES
#define MRQ_ELEMENT_SIZE	1024 //original value was 1024  Size of each element of the memory region: 1k
#define MRQ_MSG_SIZE		1024 // original value was 1024 Size of each element of the memory region: 1k


#define MAX_ID_LENGTH 256
#define MAX_KEY_LENGTH 64
#define HASH 0

#define TU_LITTLE_ENDIAN 1 // This affect when a  number is stored between pages. See tucana_messages.c

/*Client side*/
#define CLI_RECV_THREADS 0      /*1 receiving is done with threads gesalous 0 --> receive is perfromed with spinning threads*/
#define CLI_RECV_WHILE 0        /*1 receiving is done by the YCSB threads, but a single threads is receiving until it gets its own message*/


//#define HostPort "127.0.0.1:2181"
//#define HostPort "10.10.10.4:2181"
//#define HostPort "192.168.2.106:2181" //Server sith6
//#define HostPort "192.168.2.106:2181" //Server sith5
//#define HostPort "192.168.1.244:2181" //Server jedi4
//#define HostPort "192.168.1.124:2181" //Server sith4
//#define HostPort "192.168.1.125:2181" //Server sith5
#define zookeeper_host_port "192.168.1.134:2181" //Server tie4

//TODO move properties to a configuration file
#define RDMA_IP_FILTER "192.168.4."

#define TU_SEMAPHORE 1
#define TU_RDMA 1	// 1 RDMA , 0 ZMQ
#define TU_RDMA_SINGLE_MESSAGE 1 //1 puts as a single message, 0 puts with several messages, each of 1K, although all sent together

#define TU_FAKE_YCSB 0  //Only YCSB and nothing else is run
#define TU_FAKE_SEND 0 // Request is not send
#define TU_FAKE_RECV 0	//We send but we dont process the received messages
#define TU_FAKE_PAYLOAD 0
#define FAKE_ONLY_HDR 1
#define FAKE_ONLY_PAYLOAD 0

#define TU_FAKE_BTREE 0 //1 if the betree at the server is a fake one

#define SINGLE_REGION 0
#define TU_MEMORY_SEQ 1 // Memory is allocated sequentially, even with MemoryRegions

#define TU_TIMING	0 //We measure the time needed in each phase

#define TU_RDMA_CONN_PER_REGION 0 // 1 RDMA connection per region, 0 RDMA connection per server
#define TU_RDMA_CONN_PER_SERVER (!TU_RDMA_CONN_PER_REGION)

#ifdef TU_RDMA_CONN_PER_SERVER
/*in case of CONN_PER_SERVER*/
#define NUM_OF_CONNECTIONS_PER_SERVER 64
#else
#define NUM_OF_CONNECTIONS_PER_SERVER 1
#endif

#define SIZEUINT32_T (sizeof(uint32_t))
#define SIZEUINT32_T_2 (sizeof(uint32_t) << 1)

#define KREON_KEY_NOT_FOUND 2

//#define WORKER_THREADS_PER_SPINNING_THREAD 4


typedef struct tu_data_message
{
#if TU_SEMAPHORE
	sem_t sem;
#endif
	/*Inform server where we expect the reply*/
	void* reply;
	volatile uint32_t reply_length;

	uint32_t pay_len;	  //Size of the payload
	uint32_t padding_and_tail;	  //padding so as MESSAGE total size is a multiple of MESSAGE_SEGMENT_SIZE
	uint16_t type;		// Type of the message: PUT_REQUEST, PUT_REPLY, GET_QUERY, GET_REPLY, etc.
	uint8_t error_code;

	uint32_t value;       //Number of operations included in the payload
	// We could also use for an error message
	uint32_t ackfirst;	// The client will send the ACK to the server- From this element
	uint32_t ack;		// The client will send the ACK to the server - Up to this one

	volatile uint64_t local_offset;  //Offset regarding the local Memory region
	volatile uint64_t remote_offset;  //Offset regarding the remote Memory region
	//From Client to head, local_offset == remote_offset
	//From head to replica1, it could be that local_offset != remote_offset
	//(real CHAIN implementation should be equal, since head only puts and tail only gets)
	//From replica-i to replica-i+1, local_offset == remote_offset
	/*<gesalous>*/
	/*for asynchronous requests*/
	void *callback_function_args;
	void (*callback_function)(void *args);
	/*</gesalous>*/

	void	*reply_message;	/* Filled by the receiving side on arrival of a message. If request_message_local_addr of
													 a received message is not NULL the receiving side uses the request_message_local_addr to
													 find the initial message and fill its reply_message field with the address of the new message*/

	void	*request_message_local_addr;  /* This field contains the local memory address of this message.
																			 * It is piggybacked by the remote side to its
																			 *  corresponding reply message. In this way
																			 *  incoming messages can be associated with
																			 *  the initial request messages*/
	void *MR;		//In case of RDMA pointer to the MR for the datapayload
	/*gesalous staff also*/
	int32_t ack_arrived;
	volatile int32_t flags;/*from most significant byte to less: <FUTURE_EXTENSION>, <FUTURE_EXTENSION>, <FUTUTE_EXTENSION>, SYNC/ASYNC(indicates if this is  a synchronous or asynchronous request*/
#ifdef CHECKSUM_DATA_MESSAGES
	unsigned long hash; // [mvard] hash of data buffer
#endif
	void *data;		/*Pointer to the first element of the Payload*/
	void *next;		/*Pointer to the "current" element of the payload. Initially equal to data*/
	void *tail;		/*Pointer to the tail that will be an integer to indicate that the data has been received*/
	uint32_t receive;
} tu_data_message_s;



#define TU_HEADER_SIZE	(sizeof(struct tu_data_message))
#define TU_TAIL_SIZE	(sizeof(uint32_t))
#define TU_HEADER_TAIL_SIZE	(TU_HEADER_SIZE + TU_TAIL_SIZE)

#define MAX_PAY_LEN_SINGLE_PACKET ( MRQ_ELEMENT_SIZE - TU_HEADER_TAIL_SIZE)

#endif
