
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <net/route.h>
#include <net/ip.h>

#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_log.h>

#define SOCKET_OPS_BASE	150
#define SOCKET_OPS_MAX	(SOCKET_OPS_BASE + 1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NightCoffee");
MODULE_DESCRIPTION("Get original ip of redirected udp packet");
MODULE_VERSION("1.0");

/* You must define the same struct in userspace */
struct udp_addr_storage {
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dest_addr;
};

/* Just modify from nf_conntrack_l3proto_ipv4.c */
static int
getudporigdst(struct sock *sk, int optval, void __user *user, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct udp_addr_storage addr;

	memset(&tuple, 0, sizeof(tuple));
	if (copy_from_user(&addr, user, sizeof(struct udp_addr_storage)) != 0)
		return -EFAULT;

	//TODO: If get local ip, it may be bind 0.0.0.0 and use recv ip by recvfromto()
	tuple.src.u3.ip = inet->inet_rcv_saddr; // get the socket local ip & port, so you must bind one IP not 0.0.0.0
	tuple.src.u.udp.port = inet->inet_sport;
	tuple.dst.u3.ip = ((struct sockaddr_in *)&(addr.dest_addr))->sin_addr.s_addr;
	tuple.dst.u.udp.port = ((struct sockaddr_in *)&(addr.dest_addr))->sin_port;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = sk->sk_protocol;

	/* Only support UDP */
	if (sk->sk_protocol != IPPROTO_UDP) {
		pr_debug("SO_ORIGINAL_DST: Not a UDP socket\n");
		return -ENOPROTOOPT;
	}
	/*
	if ((unsigned int) *len < sizeof(struct sockaddr_in)) {
		pr_debug("SO_ORIGINAL_DST: len %d not %Zu\n",
			 *len, sizeof(struct sockaddr_in));
		return -EINVAL;
	}*/

	h = nf_conntrack_find_get(sock_net(sk), NF_CT_DEFAULT_ZONE, &tuple);
	if (h) {
		struct sockaddr_in sin;
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

		sin.sin_family = AF_INET;
		sin.sin_port = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u.udp.port;
		sin.sin_addr.s_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u3.ip;
		memset(sin.sin_zero, 0, sizeof(sin.sin_zero));



		pr_debug("SO_ORIGINAL_DST: %pI4 %u\n",
			 &sin.sin_addr.s_addr, ntohs(sin.sin_port));
		nf_ct_put(ct);
		if (copy_to_user(user, &sin, sizeof(sin)) != 0)
			return -EFAULT;
		else
			return 0;
	}
	pr_debug("SO_ORIGINAL_DST: Can't find %pI4/%u-%pI4/%u.\n",
		 &tuple.src.u3.ip, ntohs(tuple.src.u.udp.port),
		 &tuple.dst.u3.ip, ntohs(tuple.dst.u.udp.port));
	return -ENOENT;
}

static struct nf_sockopt_ops so_getudporigdst = {
	.pf		= PF_INET,
	.get_optmin	= SOCKET_OPS_BASE,
	.get_optmax	= SOCKET_OPS_MAX,
	.get		= getudporigdst,
	.owner		= THIS_MODULE,
};

static int __init udp_oridst_init(void)
{
	int ret = 0;
	ret = nf_register_sockopt(&so_getudporigdst);
	if (ret < 0) {
		printk(KERN_ERR "Unable to register UDP_ORIDST module\n");
		nf_unregister_sockopt(&so_getudporigdst);
		return ret;
	}
	printk("register UDP_ORIDST module successful\n");
	return ret;
}
static void __exit udp_oridst_fini(void)
{
	nf_unregister_sockopt(&so_getudporigdst);
}

module_init(udp_oridst_init);
module_exit(udp_oridst_fini);
