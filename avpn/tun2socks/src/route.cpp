

#include <stdio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <sys/types.h>

extern "C" {
#include <libnetlink.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
}

#include <unistd.h>
#include <string.h>
#include <sys/uio.h>

#include "route.hpp"

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
	return -1;
	rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	fprintf(stderr,"\nattr len=%d\n",n->nlmsg_len);
	return 0;
}

int nl_add_route(std::uint32_t destination, std::uint32_t gateway)
{
	struct rtnl_handle rth;
	if (rtnl_open(&rth, 0) != 0)
		return -1;

	struct sockaddr_nl nladdr;
	int status;

	__u32 index=1; /* Output Interface ::: eth0 */
	__u32 source=0;

	// structure of the netlink packet.
	struct
	{
	struct nlmsghdr n;
	struct rtmsg r;
	char buf[1024];
	} req;

	// Forming the iovector with the netlink packet.
	struct iovec iov = { (void*)&req.n, req.n.nlmsg_len };

	// Forming the message to be sent.
	struct msghdr msg = { (void*)&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };


	char mxbuf[256];
	struct rtattr * mxrta = (rtattr *)mxbuf;
	unsigned mxlock = 0;
	memset(&req, 0, sizeof(req));

	// Initialisation of a few parameters
	memset(&nladdr,0,sizeof(nladdr));
	nladdr.nl_family= AF_NETLINK;
	nladdr.nl_pid=0;
	nladdr.nl_groups=0;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWROUTE;

	req.r.rtm_family = AF_INET;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;
	req.r.rtm_dst_len=24;
	req.r.rtm_src_len=0;
	req.r.rtm_tos=0;
	req.r.rtm_flags=RT_TABLE_MAIN;


	mxrta->rta_type = RTA_METRICS;
	mxrta->rta_len = RTA_LENGTH(0);

	mxrta = (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len));
	memcpy(RTA_DATA(mxrta),mxbuf,0);
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + mxrta->rta_len;

	// RTA_DST and RTA_GW are the two esential parameters for adding a route,
	// there are other parameters too which are not discussed here. For ipv4,
	// the length of the address is 4 bytes.

	addattr_l(&req.n, sizeof(req), RTA_OIF,&index, 4);
	addattr_l(&req.n, sizeof(req), RTA_SRC,&source, 4);
	addattr_l(&req.n, sizeof(req), RTA_DST, &destination, 4);
	addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gateway, 4);


	// sending the packet to the kernel.
	status = rtnl_send(&rth, &msg, 0);

	fprintf(stderr,"\nstatus=%d",status);

	rtnl_close(&rth);

	return 0;
}