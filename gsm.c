#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char *, int);
void print_ip_packet(const u_char *, int);
void print_ip_packet2(const u_char *, int);
void print_tcp_packet(const u_char *, int);
void print_tcp_packet2(const u_char *, int);
void print_udp_packet(const u_char *, int);
void print_icmp_packet(const u_char *, int);
void PrintData(const u_char *, int);
time_t now;
struct tm *local;
char new[32], old[32];
char temp1[16], temp2[16];
FILE *logfile, *session;
struct sockaddr_in source, dest;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j, s = 0;
int hours, minutes, seconds;

int main(int argc, char **argv)
{
	pcap_if_t *alldevsp, *device;
	pcap_t *handle;

	char errbuf[100], *devname, devs[100][100];
	int count = 1, n;

	//tim kiem tat ca card mang
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("Không có thiết bị nào được tìm thấy!  %s", errbuf);
		exit(1);
	}

	//Hien thi tat ca card mang co san
	printf("Danh sách thiết bị:\n");
	for (device = alldevsp; device != NULL; device = device->next)
	{
		//get name
		printf("%d. %s", ++i, device->name);

		//Mo ta
		if (device->description)
			printf(" (%s)", device->description);

		//get ip
		for (pcap_addr_t *a = device->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
				printf(" %s", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
		}
		printf("\n");

		if (device->name != NULL)
		{
			strcpy(devs[count], device->name);
		}
		count++;
	}

	//Lay card mang de bat goi tin
	printf("Nhập số thứ tự của thiết bị để tiến hành bắt gói tin : ");
	scanf("%d", &n);

	devname = devs[n];
	printf("Tiến hành bắt gói tin trên card mạng: %s \n", devname);

	//Mo card mang de bat goi tin
	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);

	//mo file pcap
	pcap_dumper_t *dumpFile = pcap_dump_open(handle, "capture.pcap");
	if (handle == NULL)
	{
		fprintf(stderr, "Không thể mở card mạng %s : %s\n", devname, errbuf);
		exit(1);
	}

	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
	{
		printf("Không thể tạo file log");
	}

	session = fopen("session.txt", "w");
	if (session == NULL)
	{
		printf("Không thể tạo file session");
	}

	//lap lai de bat goi tin lien tuc
	pcap_loop(handle, -1, process_packet, (unsigned char *)dumpFile);
	pcap_dump_close(dumpFile);
	fclose(session);
	return 0;
}

void process_packet(u_char *dumpFile, const struct pcap_pkthdr *header, const u_char *buffer)
{
	pcap_dump(dumpFile, header, buffer);
	int size = header->len;

	//Get IP Header
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check Protocol
	{

	case 1: //ICMP Protocol
		++icmp;
		print_icmp_packet(buffer, size);
		break;

	case 2: //IGMP Protocol
		++igmp;
		break;

	case 6: //TCP Protocol
		++tcp;
		print_tcp_packet(buffer, size);
		//print_tcp_packet2(buffer , size);
		break;

	case 17: //UDP Protocol
		++udp;
		print_udp_packet(buffer, size);
		break;

	default: //Other Protocol
		++others;
		break;
	}

	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp, udp, icmp, igmp, others, total);
}

//ethernet_header
void print_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(logfile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	fprintf(logfile, "   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}

//ethernet_header2
void print_ethernet_header2(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	//print Ethernet
	fprintf(session, "\nMAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X --> %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}

//ip_packet
void print_ip_header(const u_char *Buffer, int Size)
{
	print_ethernet_header(Buffer, Size);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   |-IP Version        : %d\n", (unsigned int)iph->version);
	fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	fprintf(logfile, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph->id));
	fprintf(logfile, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
	fprintf(logfile, "   |-Protocol : %d\n", (unsigned int)iph->protocol);
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(iph->check));
	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
	strcpy(temp1, inet_ntoa(source.sin_addr));
	strcpy(temp2, inet_ntoa(dest.sin_addr));
	strcpy(new, strcat(temp1, temp2));
}

//ip_header2
void print_ip_header2(const u_char *Buffer, int Size)
{

	//define
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	//print IP address
	fprintf(session, "IP:%16s -->", inet_ntoa(source.sin_addr));
	fprintf(session, "%16s\t\t", inet_ntoa(dest.sin_addr));
}

//tcp_packet
void print_tcp_packet(const u_char *Buffer, int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	fprintf(logfile, "\n\n_________________________________%d. TCP Packet_________________________________\n", total);

	print_ip_header(Buffer, Size);

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "   |-Source Port      : %u\n", ntohs(tcph->source));
	fprintf(logfile, "   |-Destination Port : %u\n", ntohs(tcph->dest));
	fprintf(logfile, "   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	fprintf(logfile, "   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
	fprintf(logfile, "   |-Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	fprintf(logfile, "   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	fprintf(logfile, "   |-Push Flag            : %d\n", (unsigned int)tcph->psh);
	fprintf(logfile, "   |-Reset Flag           : %d\n", (unsigned int)tcph->rst);
	fprintf(logfile, "   |-Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	fprintf(logfile, "   |-Finish Flag          : %d\n", (unsigned int)tcph->fin);
	fprintf(logfile, "   |-Window         : %d\n", ntohs(tcph->window));
	fprintf(logfile, "   |-Checksum       : %d\n", ntohs(tcph->check));
	fprintf(logfile, "   |-Urgent Pointer : %d\n", tcph->urg_ptr);
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA Dump                         ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "TCP Header\n");
	PrintData(Buffer + iphdrlen, tcph->doff * 4);

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + header_size, Size - header_size);

	fprintf(logfile, "______________________________________END______________________________________\n");

	//get time
	time(&now);
	local = localtime(&now);
	hours = local->tm_hour;
	minutes = local->tm_min;
	seconds = local->tm_sec;

	if (old != NULL && (strcmp(old, new) == 0))
		return;
	else
		strcpy(old, new);
	++s;

	//SYN-ACK
	if (((unsigned int)tcph->ack == 1) && ((unsigned int)tcph->syn == 1))
	{
		fprintf(session, "%4d. [SYN-ACK]\t [%02d:%02d:%02d] ", s, hours, minutes, seconds);
		print_ip_header2(Buffer, Size);
		fprintf(session, "Port: %5u --> %u\n", ntohs(tcph->source), ntohs(tcph->dest));
		return;
	}

	//ACK
	if ((unsigned int)tcph->ack == 1)
		fprintf(session, "%4d. [ACK]\t\t [%02d:%02d:%02d] ", s, hours, minutes, seconds);
	//SYN
	else if ((unsigned int)tcph->syn == 1)
		fprintf(session, "%4d. [SYN]\t\t [%02d:%02d:%02d] ", s, hours, minutes, seconds);

	//port
	print_ip_header2(Buffer, Size);
	fprintf(session, "Port: %5u --> %5u\n", ntohs(tcph->source), ntohs(tcph->dest));
}

//udp
void print_udp_packet(const u_char *Buffer, int Size)
{

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct udphdr *udph = (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	fprintf(logfile, "\n\n_________________________________%d. UDP Packet_________________________________\n", total);

	print_ip_header(Buffer, Size);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "   |-Source Port      : %d\n", ntohs(udph->source));
	fprintf(logfile, "   |-Destination Port : %d\n", ntohs(udph->dest));
	fprintf(logfile, "   |-UDP Length       : %d\n", ntohs(udph->len));
	fprintf(logfile, "   |-UDP Checksum     : %d\n", ntohs(udph->check));

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof udph);

	fprintf(logfile, "Data Payload\n");

	PrintData(Buffer + header_size, Size - header_size);

	fprintf(logfile, "______________________________________END______________________________________\n");
}

//icmp
void print_icmp_packet(const u_char *Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	fprintf(logfile, "\n\n_________________________________%d. ICMP Packet_________________________________\n", total);

	print_ip_header(Buffer, Size);

	fprintf(logfile, "\n");

	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, "   |-Type : %d", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile, "  (TTL Expired)\n");
	}
	else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile, "  (ICMP Echo Reply)\n");
	}

	fprintf(logfile, "   |-Code : %d\n", (unsigned int)(icmph->code));
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(icmph->checksum));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof icmph);

	fprintf(logfile, "Data Payload\n");

	PrintData(Buffer + header_size, (Size - header_size));

	fprintf(logfile, "______________________________________END______________________________________\n");
}

void PrintData(const u_char *data, int Size)
{
	int i, j;
	for (i = 0; i < Size; i++)
	{
		if (i != 0 && i % 16 == 0)
		{
			fprintf(logfile, "         ");
			for (j = i - 16; j < i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(logfile, "%c", (unsigned char)data[j]);
				else
					fprintf(logfile, ".");
			}
			fprintf(logfile, "\n");
		}

		if (i % 16 == 0)
			fprintf(logfile, "   ");
		fprintf(logfile, " %02X", (unsigned int)data[i]);

		if (i == Size - 1)
		{
			for (j = 0; j < 15 - i % 16; j++)
			{
				fprintf(logfile, "   ");
			}

			fprintf(logfile, "         ");

			for (j = i - i % 16; j <= i; j++)
			{
				if (data[j] >= 32 && data[j] <= 128)
				{
					fprintf(logfile, "%c", (unsigned char)data[j]);
				}
				else
				{
					fprintf(logfile, ".");
				}
			}

			fprintf(logfile, "\n");
		}
	}
}
