#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TUN_DEVICE "tun0"
#define SOURCE_IP  "5.6.7.8"

#define IPV4_CHECKSUM_OFFSET 10
#define IPV4_SRC_IP_OFFSET   12
#define IPV4_DST_IP_OFFSET   16

int
get_destination(unsigned char *dst_ip)
{
    int ret;
    struct addrinfo *res = NULL;

    ret = getaddrinfo("app2", "80", NULL, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo returned %i\n", ret);
        return -1;
    }

    for (struct addrinfo *traverse = res; traverse; traverse = traverse->ai_next) {
        if (traverse->ai_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)traverse->ai_addr;

            memcpy(dst_ip, &addr->sin_addr, sizeof(addr->sin_addr));
            return 0;
        }
    }

    fprintf(stderr, "Couldn't resolve destination IP\n");
    return -1;
}

void
recompute_checksum(unsigned char *packet)
{
    unsigned int len = (packet[0] & 0xf) * 4, checksum = 0;

    for (unsigned int k = 0; k < len; k += 2) {
        unsigned short num = (packet[k] << 8) | packet[k + 1];

        if (k == IPV4_CHECKSUM_OFFSET) {
            continue;
        }

        checksum += num;
        while (checksum > 0xffff) {
            checksum = (checksum & 0xffff) | (checksum >> 16);
        }
    }

    checksum = (~checksum) & 0xffff;
    packet[IPV4_CHECKSUM_OFFSET] = (checksum >> 8);
    packet[IPV4_CHECKSUM_OFFSET + 1] = checksum & 0xff;
}

int
set_address_and_bring_up(void)
{
    int ret = -1, sock;
    struct ifreq ifr = {.ifr_name = TUN_DEVICE};
    struct sockaddr_in addr = {.sin_family = AF_INET};

    inet_pton(AF_INET, SOURCE_IP, &addr.sin_addr);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (ioctl(sock, SIOCSIFADDR, &ifr) == -1) {
        perror("ioctl (SIOCSIFADDR)");
        goto done;
    }

    ifr.ifr_flags = IFF_UP;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl (SIOCSIFFLAGS)");
        goto done;
    }

    ret = 0;

done:
    close(sock);
    return ret;
}

int
tun_device_create(void)
{
    int fd;
    struct ifreq ifr = {.ifr_name = TUN_DEVICE, .ifr_flags = IFF_TUN | IFF_NO_PI};

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl (TUNSETIFF)");
        goto error;
    }

    if (set_address_and_bring_up() != 0) {
        goto error;
    }

    return fd;

error:
    close(fd);
    return -1;
}

int
main()
{
    int ret = 0, tun_fd;
    unsigned char dst_ip[4];
    char dst_ip_str[INET_ADDRSTRLEN];
    unsigned char packet[] = {
        0x45, 0x00, 0x00, 0x54, 0x3a, 0x58, 0x40, 0x00, 0x40, 0x01, 0x03, 0x9d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x48, 0xc1, 0x00, 0x03, 0x00, 0x01, 0xa1, 0x81, 0x3a, 0x65, 0x00, 0x00,
        0x00, 0x00, 0x0d, 0x81, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

    inet_pton(AF_INET, SOURCE_IP, packet + IPV4_SRC_IP_OFFSET);

    if (get_destination(dst_ip) != 0) {
        return 1;
    }
    printf("Destination IP: %s\n", inet_ntop(AF_INET, dst_ip, dst_ip_str, sizeof(dst_ip_str)));
    fflush(stdout);
    memcpy(packet + IPV4_DST_IP_OFFSET, dst_ip, sizeof(dst_ip));

    recompute_checksum(packet);

    tun_fd = tun_device_create();
    if (tun_fd < 0) {
        return 1;
    }

    switch (fork()) {
    case -1:
        perror("fork");
        ret = 1;
        goto done;
    case 0: break;
    default: goto done;
    }

    do {
        sleep(1);
        printf("Emitting packet\n");
    } while (write(tun_fd, packet, sizeof(packet)) > 0);

done:
    close(tun_fd);
    return ret;
}
