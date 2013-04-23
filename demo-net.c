/*
 * Use the TCP/IP stack in the rump kernel to open a TCP connection
 * to vger.kernel.org port 80 and get the main page.
 */

#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>
#include <rump/netconfig.h>

void rumpkern_demo(void);

#define IFNAME "virt0"
#define WANTHTML "GET / HTTP/1.0\n\n"
#define BUFSIZE (64*1024)

/* vger.kernel.org in network byte order ... or did you want me to do DNS? */
#define DESTADDR 0x43b484d1

void
rumpkern_demo(void)
{
	struct sockaddr_in sin;
	char *buf;
	ssize_t nn, off;
	int error;
	int s;

	/* create interface and configure an address for it */
	error = rump_pub_netconfig_ifcreate(IFNAME);
 	error = rump_pub_netconfig_dhcp_ipv4_oneshot(IFNAME);
	if (error) {
		printk(KERN_INFO "failed to configure networking %d\n", error);
		return;
	}

	s = rump_sys_socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1) {
		printk(KERN_INFO "you're mean! no sucket for you!\n");
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = DESTADDR;
	if (rump_sys_connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		printk(KERN_INFO "could not connect\n");
		return;
	}

	nn = rump_sys_write(s, WANTHTML, sizeof(WANTHTML)-1);
	printk(KERN_INFO "wrote http request, rv %zd\n", nn);

	buf = kmalloc(BUFSIZE, GFP_KERNEL);
	off = 0;
	do {
		nn = rump_sys_read(s, buf+off, (BUFSIZE-off)-1);
		off += nn;
		BUG_ON(off >= BUFSIZE);
	} while (nn > 0);
	if (nn == -1) {
		printk(KERN_INFO "read failed: %zd\n", nn);
		return;
	}

	printk(KERN_INFO "read %zd bytes\n", off);

	/* display last 500 bytes of delicious info */
	buf[off] = '\0';
	off -= 500;
	if (off < 0)
		off = 0;
	printk(KERN_INFO "that was an educational experience.  "
	    "we learned:\n");
	printk(KERN_INFO "%s", &buf[off]);

	kfree(buf);
}
