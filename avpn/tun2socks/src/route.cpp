
#ifdef __linux__
#include <unistd.h>

extern "C" {
#include <libnetlink.h>
}

typedef struct _request
{
    struct nlmsghdr netlink_header;
    struct rtmsg rt_message;
    char buffer[1024];
} req_t;

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
    /* alen is the length of the data. Add sizeof(struct rtattr) to it to accomodate
    type, length, value format for rtattr */
    int len = RTA_LENGTH(alen); // (RTA_ALIGN(sizeof(struct rtattr)) + (len))
    struct rtattr *rta;
    /* size of request should not be violated*/
    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
            return -1;

    /* go to end of buffer in request data structure*/
    rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
    /* specify attribute using TLV format*/
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    /* increase the nlmsg_len to accomodate the added new attribute*/
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
    return 0;
}


static void initialisation(req_t& request, uint32_t gateway, int index)
{
    memset(&request, 0, sizeof(request));
    /* set the nlmsg_len = nl header + underlying structure*/
    request.netlink_header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); /*NLMSG_HDRLEN + sizeof(struct rtmsg);*/
    /* set the flags that facilitates adding a route in routing table*/
    request.netlink_header.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;
    /* note that inet_rtm_newroute() is the fn in kernel which will be eventually called to add a new route in routing table*/
    request.netlink_header.nlmsg_type = RTM_NEWROUTE;
    /* Now filling the rtmsg*/
    request.rt_message.rtm_family = AF_INET;
    request.rt_message.rtm_table = RT_TABLE_MAIN;
    request.rt_message.rtm_protocol = RTPROT_STATIC;/*Route installed during boot*/
    request.rt_message.rtm_scope = RT_SCOPE_UNIVERSE;
    request.rt_message.rtm_type = RTN_UNICAST; /*Gateway or direct route  */

    /* Add routing info*/
    addattr_l(&request.netlink_header, sizeof(request), RTA_GATEWAY, &gateway,    sizeof(gateway));

	/* mask */
//	request.rt_message.rtm_dst_len = 24;

	int32_t dst = 0;

	addattr_l(&request.netlink_header, sizeof(request), RTA_DST,     &dst,   sizeof(dst));
	addattr32(&request.netlink_header, sizeof(request), RTA_OIF,     index);
    /* For adding a route, the gateway, destination address and the interface
    will suffice, now the netlink packet is all set to go to the kernel*/
}

static void send_request(int fd, req_t& request)
{
    int rc = 0;


	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0; /* For Linux Kernel  */
    nladdr.nl_groups = 0;

	struct iovec iov = { (void*)&request.netlink_header, request.netlink_header.nlmsg_len };

    struct msghdr msg = {
        (void*)&nladdr, sizeof(nladdr),
        &iov,   1,
        NULL,   0,
        0
    };
    rc = sendmsg(fd, &msg, 0);
    printf("bytes send = %d\n", rc);
}

int nl_add_route(int ifindex, uint32_t gateway)
{
	struct sockaddr_nl la;
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(fd < 0){
		printf("socket creation failed\n");
		_exit(1);
	}
	bzero(&la, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_pid = 0;
	la.nl_groups = 0;

	if(bind(fd, (struct sockaddr*) &la, sizeof(la)) < 0){
			printf("Bind failed\n");
			return -1;
	}

	req_t request;

	initialisation(request, gateway, ifindex);
	send_request(fd, request);
	close(fd);
	return 0;
}
#endif