#ifndef __STUN_CLI_H__
#define __STUN_CLI_H__

#include <stdint.h>
#include "list.h"

typedef enum
{
	NAT_TYPE_BLOCKED = 0,
	NAT_TYPE_OPEN_INTERNET,
	NAT_TYPE_FULL_CONE_NAT,
	NAT_TYPE_RESTRIC_NAT,
	NAT_TYPE_PORT_RESTRIC_NAT,
	NAT_TYPE_SYMMETRIC_NAT,
	NAT_TYPE_UNKNOWN,
} nat_type_e;

typedef enum
{
	MSG_TYPE_BINDING_REQUEST = 0x0001,
	MSG_TYPE_BINDING_RESPONSE = 0x0101,
	MSG_TYPE_BINDING_ERR_RESPONSE = 0x0111,

	MSG_TYPE_SHARED_SECRET_RESUEST = 0x0002,
	MSG_TYPE_SHARED_SECRET_RESPONSE = 0x0102,
	MSG_TYPE_SHARED_SECRET_ERR_RESPONSE = 0x0112,
} msg_type_e;

typedef enum
{
	ATTR_TYPE_MAPPED_ADDRESS = 1,
	ATTR_TYPE_RESPONSE_ADDRESS = 2,
	ATTR_TYPE_CHANGE_REQUEST = 3,
	ATTR_TYPE_SOURCE_ADDRESS = 4,
	ATTR_TYPE_CHANGED_ADDRESS = 5,
	ATTR_TYPE_USERNAME = 6,
	ATTR_TYPE_PASSWORD = 7,
	ATTR_TYPE_MESSAGE_INTEGRITY = 8,
	ATTR_TYPE_ERROR_CODE = 9,
	ATTR_TYPE_UNKNOWN_ATTRIBUTES = 10,
	ATTR_TYPE_REFLECTED_FROM = 11,
} attr_type_e;

#define DEFAULT_STUN_SERVER_PORT 3478
#define DEFAULT_LOCAL_PORT 34780
#define MAX_STUN_MESSAGE_LENGTH 512


#define ADDERSS_FAMILY_IPV4 1
#define ADDRESS_FAMILY_IPV6 2
#define ATTR_CHANGE_IP_FLAG  0x04
#define ATTR_CHANGE_PORT_FLAG 0x02

typedef struct
{
	uint16_t msgtype;
	uint16_t msglen; // length of stun body
	uint8_t tid[16]; // Transaction ID
} stun_msghdr_t;

typedef struct
{
	uint16_t type;
	uint16_t length;
} stun_attrhdr_t;

typedef struct
{
	stun_msghdr_t msghd;
	struct list_head attr_hd;
} msg_pkg_t;

typedef struct
{
	uint8_t padding;
	uint8_t famliy;
	uint16_t port; // network byte order
	union
	{
		uint32_t ip4; // network byte order
		uint8_t ip6[16];
	};
} stun_attr_addr_t;

typedef struct
{
	struct list_head list;
	stun_attrhdr_t attrhdr;
	union
	{
		stun_attr_addr_t address;
		uint32_t change_request_flag;
		uint8_t passwd[128];
		uint8_t username[128];
		uint8_t sha1[128];
		uint16_t errcode;
	};
} attr_node_t;

#endif

