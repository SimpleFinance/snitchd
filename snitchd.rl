// vi::syntax=c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/dns_resolver.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <stdbool.h>

#define DEBUG(fmt, args...) do { printk("snitchd: "fmt"\n", ## args); } while (0)

// this is how we get at the physical memory resources available to the kernel
extern struct resource iomem_resource;

// module parameters (sent in via insmod command line)
int interval = 900;
char* graphite_prefix = NULL;
char* graphite_host = "127.0.0.1";
int graphite_port = 2003;
char* pan_prefix = NULL;

module_param(interval, int, S_IRUGO);
module_param(graphite_prefix, charp, S_IRUGO);
module_param(graphite_host, charp, S_IRUGO);
module_param(graphite_port, int, S_IRUGO);
module_param(pan_prefix, charp, S_IRUGO);

// we'll need to start a worker kthread to run in the background
struct task_struct *snitchd_watcher_task;

// this is the result of each scant sta
typedef struct snitchd_counts_s {
    size_t bytes_scanned;
    long unsigned int scan_duration_ms;
    unsigned int pans;
    unsigned int ssns;
    unsigned int routing_numbers;
    unsigned int names;
    unsigned int emails;
} snitchd_counts;

// Luhn checksum for detecting valid PANs
// Borrowed with modifications from http://rosettacode.org/wiki/Luhn_test_of_credit_card_numbers#C
static bool luhn(const char* p, const unsigned int length)
{
    const int m[] = {0,2,4,6,8,1,3,5,7,9}; // mapping for rule 3
    int i, digit, odd = 1, sum = 0, digitcount = 0;
    for (i = length; i--; odd = !odd) {
        if ((p[i] >= '0') && (p[i] <= '9'))
        {
            digitcount += 1;
            digit = p[i] - '0';
            sum += odd ? digit : m[digit];
        }
    }
 
    return (digitcount >= 13) && (sum != 0) && ((sum % 10) == 0);
}

static bool isprefix(const char* prefix, const char* buf, const unsigned int buf_length)
{
    if (buf_length > strlen(prefix))
    {
        if (0 == strncmp(prefix, buf, strlen(prefix)))
        {
            return true;
        }
    }
    return false;
}

// start defining the Ragel state machine
%%{
    machine snitchd_search;
    write data;
}%%

static void snitchd_search_page(void* ptr, size_t size, snitchd_counts* counts) {
    char* p = ptr;
    char* pe = ptr + size;
    int cs = 0;

    // remember the start of each PAN so we can go back and check Luhn values
    char* pan_start = NULL;

    %%{
        # a PAN is 13-19 digits that pass a Luhn check
        pan = (digit {13,19})
        >{ pan_start = p; }
        @{
            if (luhn(pan_start, p - pan_start + 1))
            {
                // if a PAN prefix was specified, only count values with that prefix
                if ((pan_prefix == NULL) || isprefix(pan_prefix, pan_start, p - pan_start + 1))
                {
                    counts->pans++;
                }
            }
        };

        # SSN (with dashes only, for now)
        ssn = (digit{3} '-' digit{2} '-' digit{4})
        @{
            counts->ssns++;
        };

        # an email is *@*.tld, minus a few domains that show up a lot in a default ubuntu install
        email_domain = (((alnum | '.') + ) - (("lists." any+) | "debian" | "ubuntu" | "canonical"));
        email = (((alnum | '.' | '+') +) . '@' . email_domain . (".com" | ".org" | ".net"))
        @{
            counts->emails++;
        };

        # load some big lists of common US first and last names (from census data)
        # Take out some last names at also show up a lot in software source/docs.
        include "first_names.rl";
        include "last_names.rl";
        name = ((firstname | lastname) - ("shell"i | "block"i | "cloud"i | "driver"i | "small"i))
        @{
            counts->names++;
        };

        # look at a giant list of routing numbers pulled from The Fed's site
        include "routing_numbers.rl";
        routing_number = (routingnumber)
        @{
            counts->routing_numbers++;
        };

        start := ((any*) :> (email | pan | ssn | name | routing_number));

        # Initialize and execute.
        write init;
        write exec;
    }%%
}

// select "struct resource*" entries we'd like to scan
static bool snitchd_should_scan_resource(struct resource* res)
{
    // we only want to scan normal RAM, not IO busses and stuff
    if (0 != strcmp(res->name, "System RAM"))
    {
        return false;
    }

    // for whatever reason, there is a 127 MB thing on m3.xlarges that can't be mapped
    if (((size_t) (res->end - res->start))/(1024*1024) < 128)
    {
        return false;
    }
    return true;
}

static int snitchd_scan(snitchd_counts* counts)
{
    struct resource* res = NULL;

    resource_size_t cur = 0;
    resource_size_t size = 0;
    struct page* page_ptr = NULL;
    void* vmem_ptr = NULL;

    unsigned long resources_scanned = 0;
    unsigned long pages_scanned = 0;
    unsigned long num_resources = 0;
    unsigned long approx_total_pages = 0;

    // first loop through and estimate how many total pages there are
    for (res = iomem_resource.child; res ; res = res->sibling) {
        if (snitchd_should_scan_resource(res))
        {
            num_resources++;
            approx_total_pages += (res->end - res->start) / PAGE_SIZE;
        }
    }

    // scan through all the IO resorces looking for "System RAM" entries
    for (res = iomem_resource.child; res ; res = res->sibling) {
        if (!snitchd_should_scan_resource(res))
        {
            continue;
        }

        // read out each physical page of the resource
        cur = res->start;
        while (cur <= res->end) {
            // scan up to PAGE_SIZE at a time
            size = min((size_t) PAGE_SIZE, (size_t) (res->end - cur + 1));

            if (size == PAGE_SIZE)
            {
                // convert the physical memory pointer to a "page frame number", then
                // map it to a kernel page pointer.
                page_ptr = pfn_to_page(cur >> PAGE_SHIFT);

                // map the page into virtual memory
                vmem_ptr = kmap(page_ptr);

                // search the page we mapped into virtual memory
                snitchd_search_page(vmem_ptr, size, counts);

                // unmap it
                kunmap(page_ptr);

                counts->bytes_scanned += size;
            }
            cur += size;

            // sleep briefly every so often so we don't chug CPU
            if ((pages_scanned % 100) == 0)
            {
                set_current_state(TASK_INTERRUPTIBLE);
                schedule_timeout(1);
                // if our thread is dying, stop now
                if (kthread_should_stop()) {
                    DEBUG("stopping active scan");
                    return -1;
                }
            }
            pages_scanned++;
            //if ((pages_scanned % 10000) == 0)
            //{
            //    DEBUG("scanned %lu/%lu pages; %lu/%lu resources; %lu/%lu MB",
            //          pages_scanned, approx_total_pages,
            //          resources_scanned, num_resources,
            //          (pages_scanned * PAGE_SIZE) / (1024 * 1024),
            //          (approx_total_pages * PAGE_SIZE) / (1024 * 1024));
            //}
        }
        resources_scanned++;
    }
    return 0;
}

void snitchd_format_graphite_report(snitchd_counts* counts, char* buf, size_t buf_size) {
    struct timeval t;
    do_gettimeofday(&t);

    memset(buf, 0, buf_size);
    snprintf(
        buf,
        buf_size - 1,
        "%s.bytes_scanned %lu %lu\n"
        "%s.scan_duration_ms %lu %lu\n"
        "%s.pans %u %lu\n"
        "%s.ssns %u %lu\n"
        "%s.routing_numbers %u %lu\n"
        "%s.names %u %lu\n"
        "%s.emails %u %lu\n",
        graphite_prefix, counts->bytes_scanned, t.tv_sec,
        graphite_prefix, counts->scan_duration_ms, t.tv_sec,
        graphite_prefix, counts->pans, t.tv_sec,
        graphite_prefix, counts->ssns, t.tv_sec,
        graphite_prefix, counts->routing_numbers, t.tv_sec,
        graphite_prefix, counts->names, t.tv_sec,
        graphite_prefix, counts->emails, t.tv_sec);
}

static int snitchd_get_graphite_addr(struct sockaddr_in* addr)
{
    int err = 0;
    char* dns_query_result = NULL;

    // call the keyutil usermode helper to resolve the specified graphite hostname
    err = dns_query(NULL, graphite_host, strlen(graphite_host), NULL, &dns_query_result, NULL);
    if (err < 0)
    {
        DEBUG("dns_query returned %d", err);
        goto done;
    }

    DEBUG("looked up %s:%d -> %s:%d",
          graphite_host, graphite_port,
          dns_query_result, graphite_port);

    // fill in the sockaddr_in structure with the result
    addr->sin_family = AF_INET;
    addr->sin_port = htons(graphite_port);
    addr->sin_addr.s_addr = in_aton(dns_query_result);

    // 0 -> success
    err = 0;
done:
    if (dns_query_result != NULL)
    {
        kfree(dns_query_result);
    }
    return err;
}

int snitchd_graphite_report(snitchd_counts* counts)
{
    int err = 0;
    char buf[512];
    struct sockaddr_in addr;
    struct socket *sock_send;
    mm_segment_t oldfs;
    struct iovec iov;
    struct msghdr msg;
    int size;
    memset(&addr, 0, sizeof(addr));

    // resolve the graphite host to a sockaddr_in structure
    err = snitchd_get_graphite_addr(&addr);
    if (err < 0)
    {
        DEBUG("error looking up graphite host");  
        goto done;
    }

    // format the report payload into a stack buffer
    snitchd_format_graphite_report(counts, buf, sizeof(buf));
    
    err = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock_send);
    if (err < 0)
    {
        DEBUG("error creating socket");  
        goto done;
    }

    err = sock_send->ops->connect(sock_send, (struct sockaddr *)&addr, sizeof(struct sockaddr), 0);
    if (err < 0)
    {
        DEBUG("error connecting socket: %d", err);
        goto done;
    }

    if (sock_send->sk == NULL)
    {
        err = -1;
        DEBUG("error: sock_send->sk is NULL");  
        goto done;
    }

    iov.iov_base = buf;
    iov.iov_len = strlen(buf);

    msg.msg_flags = 0;
    msg.msg_name = &addr;
    msg.msg_namelen  = sizeof(struct sockaddr_in);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    size = sock_sendmsg(sock_send, &msg, iov.iov_len);
    set_fs(oldfs);

    // close the socket
    sock_release(sock_send);

    DEBUG("sent %lu byte report:\n%s", strlen(buf), buf);
done:
    return err;
}

int snitchd_watcher_main(void *data)
{
    snitchd_counts counts;
    unsigned long scan_start, scan_end;

    while (!kthread_should_stop())
    {
        DEBUG("starting scan");
        // scan, storing results into the "counts" struct
        memset(&counts, 0, sizeof(counts));
        scan_start = jiffies;

        // if the scan was canceled (returns <0), break immediately
        if (0 > snitchd_scan(&counts))
        {
            break;
        }

        // otherwise mark the end of the timer
        scan_end = jiffies;
        counts.scan_duration_ms = (scan_end - scan_start) * 1000 / HZ;

        // report the counts
        snitchd_graphite_report(&counts);

        // and sleep until the next scan
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(interval * HZ);
    }
    DEBUG("watcher thread stopping");
    return 0;
}

// when the module is loaded, start our background task and return
int init_module (void)
{
    if (graphite_prefix == NULL) {
        DEBUG("graphite_prefix must be specified!");
        return -1;
    }

    DEBUG("starting (interval = %d; graphite_prefix=%s; graphite_host = %s; graphite_port = %d; pan_prefix=%s)",
            interval, graphite_prefix, graphite_host, graphite_port, pan_prefix);

    snitchd_watcher_task = kthread_run(&snitchd_watcher_main, NULL, "snitchd");
	return 0;
}

// when the module is unloaded, stop the background task
void cleanup_module(void)
{
    DEBUG("stopping watcher thread...");
    kthread_stop(snitchd_watcher_task);
}

MODULE_LICENSE("Proprietary");
