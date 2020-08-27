#include <cstdio>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <pcap.h>
#include <errno.h>
#include "iphdr.h"
#include "tcphdr.h"
#include "ethhdr.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#define PORT 4660
int netfilterswitch=NF_ACCEPT;
int flag=0;
u_int fakeseq;
Ip myip;
Mac mmac;
pcap_t* handle;
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	netfilterswitch=NF_ACCEPT;
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
		id = ntohl(ph->packet_id);
	hwph = nfq_get_packet_hw(tb);
	mark = nfq_get_nfmark(tb);
	ifi = nfq_get_indev(tb);
	ifi = nfq_get_outdev(tb);
	ifi = nfq_get_physindev(tb);
	ifi = nfq_get_physoutdev(tb);
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		IpHdr* iphdr=(IpHdr*)data;
		int ip_len=iphdr->IP_HL()*4;
		if(iphdr->ip_p==IpHdr::TCP){//if packet protocol is tcp
			TcpHdr* tcphdr=(TcpHdr*)(data+ip_len);
			int tcp_len=tcphdr->TH_OFF()*4;
			int payload_len=ntohs(iphdr->ip_len)-ip_len-tcp_len;
			if(ntohs(tcphdr->th_sport)==PORT&&tcphdr->th_flags&TH_ACK==TH_ACK&& flag==0){
				flag=1;
				fakeseq=ntohl(tcphdr->th_seq);
			}
			else if(ntohs(tcphdr->th_sport)==PORT&&tcphdr->th_flags&TH_PUSH==TH_PUSH){
				//encapsule plz
				
				//send packet plz
				netfilterswitch=NF_DROP;
			}
		}
    }
	return id;
}
Mac getmymac(struct ifreq ifr){
	Mac mymac=Mac(ifr.ifr_hwaddr); //using overloaded constructor
	return mymac;
}
Ip getmyip(struct ifreq ifr){
	Ip myip=Ip(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr); //using overloaded constructor
	return myip;
}
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	return nfq_set_verdict(qh, id, netfilterswitch, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf); //read_timeout 10
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	int sock;
	struct ifreq ifr;
	struct ifreq ifr_ip;
	memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
	memset(&ifr_ip, 0x00, sizeof(ifr));
    strcpy(ifr_ip.ifr_name, dev);
 	ifr_ip.ifr_addr.sa_family = AF_INET;

    int fd=socket(AF_INET, SOCK_DGRAM, 0);
    if((sock=socket(AF_INET, SOCK_DGRAM, 0))<0){
        perror("socket ");
    }
    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl mac");
        exit(1);
    }
	if(ioctl(fd,SIOCGIFADDR,&ifr_ip)<0){
        perror("ioctl ip");
        exit(1);
    }
	close(sock);
	///
	Ip myip=getmyip(ifr_ip);
	Mac mmac=getmymac(ifr);
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	fd = nfq_fd(h);
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);
	printf("closing library handle\n");
	nfq_close(h);
	exit(0);
}
