#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "stun_cli.h"

#define MAX_RETRIES_NUM 3

static const char* nat_type_descriptions[] =
{
	"Firewall UDP Blocked",
	"Open Internet",
	"Full Cone NAT",
	"Address Restricted Cone NAT",
	"Address and Port Restricted Cone NAT",
	"Symmetric NAT",
	"Error while detect"
};

const char* get_nat_desc(nat_type_e type)
{
	return nat_type_descriptions[type];
}

static int get_local_ipaddr(struct sockaddr_in* peer, struct sockaddr_in* lcaddr)
{
	int fd = socket (AF_INET, SOCK_DGRAM, 0);
	int ret = -1;
	socklen_t len = sizeof (struct sockaddr);

	if (fd == -1)
	{
		perror("create socket error");
		return -1;
	}

	if (connect(fd, (struct sockaddr*)peer, len) < 0)
	{
		perror("UDP connect error");
		goto out;
	}


	if (getsockname(fd, (struct sockaddr*)lcaddr, &len) < 0)
	{
		perror("getsockname error");
		goto out;
	}
	ret = 1;

out:
	close (fd);
	return  ret;
}

static void gen_random_string(char* s, const int len)
{
	static const char alphanum[] =
	    "0123456789"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz";

	int i = 0;
	for (; i < len; ++i)
	{
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
}

static msg_pkg_t* new_message_pkg(char* tid, int idlen, msg_type_e msgtype)
{
	msg_pkg_t* pkg = malloc(sizeof(msg_pkg_t));

	if (!pkg)
		return NULL;

	memset(pkg, 0, sizeof(msg_pkg_t));
	INIT_LIST_HEAD(&pkg->attr_hd);
	if (tid && idlen > 0)
	{
		memcpy(&pkg->msghd.tid, tid, idlen);
	}
	pkg->msghd.msgtype = msgtype;
	return pkg;
}

static attr_node_t* new_attr_node(attr_type_e attrtype)
{
	attr_node_t* attrnode = malloc(sizeof(attr_node_t));
	if (!attrnode )
		return NULL;

	memset(attrnode, 0, sizeof(attr_node_t));
	attrnode->attrhdr.type = attrtype;
	attrnode->attrhdr.length = 0;
	return attrnode;
}

static void release_message_pkg(msg_pkg_t* pkg)
{
	attr_node_t* node;
	attr_node_t* tmp;

	list_for_each_entry_safe(node, tmp, &pkg->attr_hd, list)
	{
		list_del(&node->list);
		free(node);
	}
	free(pkg);
}

//TLV encoded IPV4/IPV6 address attribute
static int encode_stun_attr_address(char* buf, int buflen, stun_attr_addr_t* addr)
{
	int cnt = 0;
	int captal = 4 + (ADDERSS_FAMILY_IPV4 == addr->famliy ? 4 : 16);
	char* wptr = buf;

	if (buflen < captal)
	{
		printf("encode address error: buffer overflow\n");
		return 0;
	}

	// encode pading and famliy
	wptr[0] = 0; // pading
	wptr[1] = addr->famliy;

	cnt += 2;
	wptr += 2;

	// encode port
	memcpy(wptr, &addr->port, 2);
	cnt += 2;
	wptr += 2;

	// encode IP
	if (ADDERSS_FAMILY_IPV4 == addr->famliy)
	{
		memcpy(wptr, &addr->ip4, 4);
		cnt += 4;
		wptr += 4;
	}
	else
	{
		memcpy(wptr, addr->ip6, 16);
		cnt += 16;
		wptr += 16;
	}

	return cnt;
}

static int encode_stun_attr_chang_request(char* buf, int buflen, int flags)
{
	int val = htonl(flags);
	if (buflen < 4)
		return 0;

	memcpy(buf, &val, 4);
	return 4;
}

static int encode_stun_attr(char* buf, int buflen, attr_node_t* attrnode)
{
	int cnt = 0;
	uint16_t datalen = 0;
	char data[256] = {0};
	char* wptr = buf;


	switch (attrnode->attrhdr.type)
	{
		case ATTR_TYPE_MAPPED_ADDRESS:
			break;

		case ATTR_TYPE_CHANGE_REQUEST:
			datalen = encode_stun_attr_chang_request(data, 256, attrnode->change_request_flag);
			break;
		default:
			printf("not impelement yet\n");
			break;
	}

	if (buflen < datalen + 4)
	{
		printf("encode attribute error: buffer overflow\n");
		return 0;
	}

	// load type
	wptr[0] = (attrnode->attrhdr.type >> 8) & 0xff;
	wptr[1] = attrnode->attrhdr.type & 0xff;

	wptr += 2;
	cnt += 2;

	// load data length
	wptr[0] = (datalen >> 8) & 0xff;
	wptr[1] = datalen & 0xff;

	wptr += 2;
	cnt += 2;

	if (datalen)
	{
		memcpy(wptr, data, datalen);
		cnt += datalen;
		wptr += datalen;
	}
	return cnt;
}

static int encode_stun_package(char* buf, int buflen, msg_pkg_t* pkg)
{
	int cnt = 0;
	char* wptr = buf;
	uint16_t val16;

	char data[MAX_STUN_MESSAGE_LENGTH] = {0};
	uint16_t datalen = 0;
	attr_node_t* attrnode = NULL;

	list_for_each_entry(attrnode, &pkg->attr_hd, list)
	{
		int offset = encode_stun_attr(data + datalen, MAX_STUN_MESSAGE_LENGTH - datalen, attrnode);
		if (offset <= 0)
		{
			return 0;
		}
		datalen += offset;
	}

	if (buflen < datalen + 20)
	{
		printf("error encode message package: buffer overflow\n");
		return 0;
	}

	// encode message type
	val16 = htons(pkg->msghd.msgtype);
	memcpy(wptr, &val16, 2);
	cnt += 2;
	wptr += 2;

	// encode message length
	val16 = htons(datalen);
	memcpy(wptr, &val16, 2);
	cnt += 2;
	wptr += 2;

	// encode ID or cookie
	memcpy(wptr, &pkg->msghd.tid, 16);
	cnt += 16;
	wptr += 16;

	if (datalen)
	{
		memcpy(wptr, data, datalen);
		cnt += datalen;
		wptr += datalen;
	}
	return cnt;
}

static int send_stun_package (int fd, struct sockaddr_in* peer, msg_pkg_t* pkg)
{
	char buf[MAX_STUN_MESSAGE_LENGTH] = {0};
	int ret = 0;

	ret = encode_stun_package(buf, MAX_STUN_MESSAGE_LENGTH, pkg);
	if (ret <= 0)
	{
		printf("fail to encode package...\n");
		return -1;
	}

	if (-1 == sendto(fd, buf, ret, 0, (struct sockaddr*)peer, sizeof(struct sockaddr_in )))
	{
		perror("send package error");
		return -1;
	}
	return 0;
}

static int parse_stun_attr_address( char* body, unsigned int attrlen, stun_attr_addr_t* addr)
{
	if (attrlen != 8 /* ipv4 size */ && attrlen != 20 /* ipv6 size */ )
	{
		return -1;
	}

	memcpy(addr,  body, attrlen);
	return attrlen;
}


static int parse_stun_attr(char* buf, uint16_t buflen, attr_node_t** pattrnode)
{
	attr_node_t* attrnode = new_attr_node(0);
	char* rptr = buf;
	int cnt = 0;

	if (!attrnode)
		return -1;

	memcpy(&attrnode->attrhdr, buf, sizeof(stun_attrhdr_t));
	attrnode->attrhdr.type = ntohs(attrnode->attrhdr.type);
	attrnode->attrhdr.length = ntohs(attrnode->attrhdr.length);

	rptr += sizeof(stun_attrhdr_t);
	cnt += sizeof(stun_attrhdr_t);

	switch (attrnode->attrhdr.type)
	{
		case ATTR_TYPE_MAPPED_ADDRESS:
		case ATTR_TYPE_CHANGED_ADDRESS:
		case ATTR_TYPE_SOURCE_ADDRESS:
		{
			int ret = parse_stun_attr_address(rptr, attrnode->attrhdr.length, &attrnode->address);
			if (ret <= 0)
				goto error_out;
			cnt += ret;
			rptr += ret;
			break;
		}

		default:
			printf("attribute  %d not cared\n", attrnode->attrhdr.type);
			cnt += attrnode->attrhdr.length;
			rptr += attrnode->attrhdr.length;
			break;
	}

	*pattrnode = attrnode;
	return cnt;

error_out:
	if (attrnode)
		free(attrnode);
	return -1;

}

static msg_pkg_t* parse_stun_package(char* buf, uint16_t buflen)
{
	msg_pkg_t* pkg = NULL;
	stun_msghdr_t* msghd;
	uint16_t msgtype;
	int payloadlen = 0;
	char* payload = NULL;

	if (!buf || buflen < sizeof(stun_msghdr_t) )
		return NULL;

	pkg = new_message_pkg(NULL, 0, 0);
	if (!pkg)
		return NULL;

	msghd = &pkg->msghd;
	memcpy(msghd, buf, sizeof(stun_msghdr_t));
	msghd->msgtype = ntohs(msghd->msgtype);
	msgtype = msghd->msgtype;

	payloadlen = ntohs(msghd->msglen);
	payload = buf + sizeof(stun_msghdr_t);

	while(payloadlen >= sizeof(stun_attrhdr_t) && payload < buf + buflen )
	{
		attr_node_t* attrnode = NULL;
		int offset = parse_stun_attr(payload, payloadlen, &attrnode);
		if (offset > 0 && attrnode)
		{
			list_add(&attrnode->list, &pkg->attr_hd);
			payloadlen -= offset;
			payload += offset;
		}
		else
		{
			printf("parse atrribute error: <%s> on %ld\n", buf, payload - buf);
			free(pkg);
			return NULL;
		}
	}
	return pkg;
}

static msg_pkg_t* waitfor_reply(int fd, int timeout, struct sockaddr_in* peer)
{
	int addrlen = sizeof( struct sockaddr_in);
	struct timeval tv;
	char buf[MAX_STUN_MESSAGE_LENGTH] = {0};
	int len = 0;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

	if ( (len = recvfrom(fd, buf, MAX_STUN_MESSAGE_LENGTH, 0, (struct sockaddr*)peer, &addrlen)) <= 0)
	{
		printf("recv reply error or timeout\n");
		return NULL;
	}

	return parse_stun_package(buf, len);
}

/**
* 向 srvip1:srvpt1 发送 BINDING_REQUEST
*
* 获取服务端返回的 映射地址 和 服务器陪测的第二组地址
*/
static int stun_test1(int fd, char* id,  struct sockaddr_in* peer,
                      stun_attr_addr_t* mapped_addr, stun_attr_addr_t* changed_addr)
{
	msg_pkg_t* bind_req = new_message_pkg(id, 16, MSG_TYPE_BINDING_REQUEST);
	msg_pkg_t* rply = NULL;
	int ret = -1;
	struct sockaddr_in ignaddr;

	if (!bind_req)
		return -1;

	if (send_stun_package(fd, peer, bind_req) < 0)
		return -1;

	rply = waitfor_reply(fd, 5, &ignaddr);
	if (!rply)
	{
		ret = 0;
		goto free_out;
	}
	printf("recv reply: %s\n", rply->msghd.msgtype == MSG_TYPE_BINDING_RESPONSE ? "BINDING_RESPONSE" : "mismatch type" );

	if (!list_empty(&rply->attr_hd))
	{
		attr_node_t* nd;
		list_for_each_entry(nd, &rply->attr_hd, list)
		{
			printf("\t attribute: %d\n", nd->attrhdr.type);
			if (nd->attrhdr.type == ATTR_TYPE_MAPPED_ADDRESS)
			{
				memcpy(mapped_addr, &nd->address, sizeof(stun_attr_addr_t));
			}
			else if (nd->attrhdr.type == ATTR_TYPE_CHANGED_ADDRESS)
			{
				memcpy(changed_addr, &nd->address, sizeof(stun_attr_addr_t));
			}
		}
	}
	ret = 1;
free_out:
	if (bind_req)
	{
		release_message_pkg(bind_req);
	}
	if (rply)
	{
		release_message_pkg(rply);
	}
	return ret;
}

/**
* 向 srvip1:srvpt1 发送 携带有CHANGE_REQUEST(ip+port) 的 BINDING_REQUEST
*
* 如果客户端可以收到服务器 srvip2:srvpt2（该地址信息在test1中CHANGED_ADDRESS返回）的回包，说明
* 客户处于Open Internet 或者 Full Cone NAT
*
* 如果客户端没有收到 srvip2:srvpt2 的回包，说明客户端处于Restric Cone NAT 或者 Symmetric NAT
* 需要继续检测
*/
static int stun_test2(int fd, char* id, struct sockaddr_in* peer, stun_attr_addr_t* changed_addr)
{
	msg_pkg_t* bind_req = new_message_pkg(id, 16, MSG_TYPE_BINDING_REQUEST);
	attr_node_t* attrnode = new_attr_node(ATTR_TYPE_CHANGE_REQUEST);
	msg_pkg_t* rply = NULL;
	struct sockaddr_in chsrvaddr;
	int ret = -1;

	if (!bind_req )
		return -1;

	if (!attrnode)
		goto free_out;

	attrnode->change_request_flag = ATTR_CHANGE_IP_FLAG | ATTR_CHANGE_PORT_FLAG;
	list_add(&attrnode->list, &bind_req->attr_hd);

	if (send_stun_package(fd, peer, bind_req) < 0)
	{
		goto free_out;
	}

	rply = waitfor_reply(fd, 5, &chsrvaddr);

	if (!rply)
	{
		printf("wait for change IP & port package timeout\n");
		ret = 0;
		goto free_out;
	}

	if (chsrvaddr.sin_addr.s_addr == changed_addr->ip4
	        && chsrvaddr.sin_port == changed_addr->port)
	{
		printf("test2 done success, FULL Cone or Open Internet\n");
		ret = 1;
	}
	else
	{
		printf("test2 recv reply: %s, from %s:%u, diff from changed \n",
		       rply->msghd.msgtype == MSG_TYPE_BINDING_RESPONSE ? "BINDING_RESPONSE" : "xxx",
		       inet_ntoa(chsrvaddr.sin_addr), ntohs(chsrvaddr.sin_port));
		ret = 0;
	}

free_out:
	if (bind_req)
	{
		release_message_pkg(bind_req);
	}
	if (rply)
	{
		release_message_pkg(rply);
	}
	return ret;
}

/**
* 向 srvip1:srvpt1 发送 携带有CHANGE_REQUEST(port) 的 BINDING_REQUEST
*
*
*/
static int stun_test3(int fd, char* id, struct sockaddr_in* peer, stun_attr_addr_t* changed_addr)
{
	msg_pkg_t* bind_req = new_message_pkg(id, 16, MSG_TYPE_BINDING_REQUEST);
	attr_node_t* attrnode = new_attr_node(ATTR_TYPE_CHANGE_REQUEST);
	msg_pkg_t* rply = NULL;
	struct sockaddr_in chsrvaddr;
	int ret = -1;

	if (!bind_req )
		return -1;

	if (!attrnode)
		goto free_out;

	attrnode->change_request_flag =  ATTR_CHANGE_PORT_FLAG;
	list_add(&attrnode->list, &bind_req->attr_hd);

	if (send_stun_package(fd, peer, bind_req) < 0)
	{
		goto free_out;
	}

	rply = waitfor_reply(fd, 3, &chsrvaddr);

	if (!rply)
	{
		printf("wait for change port package timeout\n");
		ret = 0;
		goto free_out;
	}

	if (chsrvaddr.sin_port == changed_addr->port)
		ret = 1;

free_out:
	if (bind_req)
	{
		release_message_pkg(bind_req);
	}
	if (rply)
	{
		release_message_pkg(rply);
	}
	return ret;
}


static nat_type_e stun_detect_nattype(const char* srvhost, const uint16_t port)
{
	struct sockaddr_in lcaddr;
	struct sockaddr_in srvaddr;
	socklen_t addrlen = sizeof (struct sockaddr);
	struct hostent* srvhostent = gethostbyname(srvhost);
	int fd;
	nat_type_e nattype = NAT_TYPE_UNKNOWN;
	char tid[16] = {0};
	stun_attr_addr_t mapped_addr;
	stun_attr_addr_t changed_addr;
	int ret;

	if (srvhostent == NULL)
	{
		printf( "No such host:%s\n", srvhost);
		return NAT_TYPE_UNKNOWN;
	}


	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd <= 0)
	{
		return NAT_TYPE_UNKNOWN;
	}
	else
	{
		int reuse_addr = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_addr, sizeof(reuse_addr));
	}

	do
	{
		int i;
		for(i = 0; srvhostent->h_addr_list[i]; i++)
		{
			printf("Server(%s) main address %s\n", srvhost,  inet_ntoa( *(struct in_addr*)srvhostent->h_addr_list[i] ) );
		}
	} while(0);

	srvaddr.sin_family = AF_INET;
	memcpy(&srvaddr.sin_addr.s_addr, srvhostent->h_addr_list[0], srvhostent->h_length);
	srvaddr.sin_port = htons(port);

	// get local IP
	memset(&lcaddr, 0, sizeof(struct sockaddr_in));
	if (get_local_ipaddr(&srvaddr, &lcaddr) < 0)
		goto close_out;

	lcaddr.sin_port = 0; // reset port
	if (bind(fd, (struct sockaddr*)&lcaddr, sizeof(lcaddr)))
	{
		if (errno == EADDRINUSE)
		{
			printf("port in use, try another port\n");
		}
		goto close_out;
	}

	// get local Port
	if (getsockname(fd, (struct sockaddr*)&lcaddr, &addrlen) < 0)
	{
		perror("getsockname error");
		goto close_out;
	}

	printf("Local address %s:%u\n", inet_ntoa(lcaddr.sin_addr), ntohs(lcaddr.sin_port));

	gen_random_string(tid, 16);

	ret = stun_test1(fd, tid, &srvaddr, &mapped_addr, &changed_addr);
	if ( ret < 0)
	{
		goto close_out;
	}
	else if (ret == 0)
	{
		nattype = NAT_TYPE_BLOCKED;
		goto close_out;
	}


	printf("Client NAT mapped address %s:%u\n",
	       inet_ntoa( *(struct in_addr*)&mapped_addr.ip4),
	       ntohs(mapped_addr.port));
	printf("Server second test address %s:%u\n",
	       inet_ntoa( *(struct in_addr*)&changed_addr.ip4),
	       ntohs(changed_addr.port)
	      );

	// compare to local host, if mapped_addr same with local host, it's Open Internet
	if (mapped_addr.ip4 == lcaddr.sin_addr.s_addr && mapped_addr.port == lcaddr.sin_port)
	{
		// FIX-ME try test2 to determining, is there a UDP Symmetric Firewall
		nattype = NAT_TYPE_OPEN_INTERNET;
		goto close_out;
	}

	// try detect Full-Cone
	ret = stun_test2(fd, tid, &srvaddr, &changed_addr);
	if (ret < 0)
	{
		goto close_out;
	}
	else if (ret > 0)
	{
		nattype = NAT_TYPE_FULL_CONE_NAT;
		goto close_out;
	}

	// try detect Symmetric NAT
	do
	{
		struct sockaddr_in srvaddr2;
		stun_attr_addr_t mapped_addr2;
		stun_attr_addr_t changed_addr2;

		srvaddr2.sin_family = AF_INET;
		srvaddr2.sin_addr.s_addr = changed_addr.ip4;
		srvaddr2.sin_port = changed_addr.port;


		ret = stun_test1(fd, tid, &srvaddr2, &mapped_addr2, &changed_addr2);
		if ( ret <= 0)
		{
			goto close_out;
		}

		// 两次映射端口不一致，Symmetric NAT
		if (mapped_addr.ip4 != mapped_addr2.ip4 || mapped_addr.port != mapped_addr2.port)
		{
			nattype = NAT_TYPE_SYMMETRIC_NAT;
			goto close_out;
		}
	} while(0);

	// detect Restric Cone or Port Restric Cone
	ret = stun_test3(fd, tid, &srvaddr, &changed_addr);
	if (ret < 0)
		goto close_out;
	else if  (ret > 0)
		nattype = NAT_TYPE_RESTRIC_NAT;
	else
		nattype =  NAT_TYPE_PORT_RESTRIC_NAT;

close_out:
	if(fd > 0)
		close(fd);
	return nattype;
}


int main(int argc, char** argv)
{
	nat_type_e nattype = stun_detect_nattype("stun.ekiga.net", 3478);
	printf("Nat type detected: %s\n", get_nat_desc(nattype));
	return 0;
}


