/**
 * @file hw2secws.c
 * @author Assaf Gadish
 *
 * @brief A dummy firewall with controlling character device.
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <asm/string.h>

#include "common.h"
#include "hw2secws_stats.h"


/*   K E R N E L   A T T R I B U T E S   */
MODULE_LICENSE("GPL");


/*   M A C R O S   */
#define INVALID_MAJOR_NUMBER (-1)
#define CLASS_NAME "hw2secws_class"
#define CHAR_DEVICE_NAME "hw2secws_char_device"
#define SYSFS_DEVICE_NAME (CLASS_NAME "_" CHAR_DEVICE_NAME)


/*   F U N C T I O N S    D E C L A R A T I O N S   */
/**
 * @brief Init the module by registering all hooks
 *
 * @return 0 on succesful initialisation, non-zero value on error
 */
static int
__init hw2secws_init(void);

/**
 * @brief Clean the module by unregistering all hooks
 */
static void
__exit hw2secws_exit(void);

/**
 * @brief Print a kernel message that indicates a packet was accepted
 */
static void
log_accept(void);

/**
 * @brief Print a kernel message that indicates a packet was dropped
 */
static void
log_drop(void);

/**
 * @brief A netfilter hook handler that always accepts the given packet
 * 
 * @param[in] priv Ignored
 * @param[in] skb The packet's socket buffer (ignored)
 * @param[in] state The packet's netfilter hook state (ignored)
 *
 * @return NF_ACCEPT
 */
static unsigned int
hw2secws_hookfn_accept(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
);

/**
 * @brief A netfilter hook handler that always drops the given packet
 * 
 * @param[in] priv Ignored
 * @param[in] skb The packet's socket buffer (ignored)
 * @param[in] state The packet's netfilter hook state (ignored)
 *
 * @return NF_DROP
 */
static unsigned int
hw2secws_hookfn_drop(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
);

static int
init_device(void);

static void
clean_device(void);

static int
register_hooks(void);

static void
unregister_hooks(void);

static ssize_t
display(struct device *dev, struct device_attribute *attr, char *buf);

static ssize_t
modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

static inline void
zero_counters(void);


/*   G L O B A L S   */
/** 
 * @brief Netfilter hook for INPUT packet chain, aka packets destinated to this machine
 */
static struct nf_hook_ops g_input_hook;

/** 
 * @brief Netfilter hook for OUTPUT packet chain, aka packets sent by this machine
 */
static struct nf_hook_ops g_output_hook;

/** 
 * @brief Netfilter hook for FORWARD packet chain, aka packets that are neither destinated to this
 *        machine nor sent by this machine
 */
static struct nf_hook_ops g_forward_hook;

/** 
 * @brief Character device of the module
 */
static struct file_operations g_file_operations = {
    .owner = THIS_MODULE
};

static int g_major_number = INVALID_MAJOR_NUMBER;
static struct class *g_hw2secws_class = NULL;
static struct device *g_hw2secws_device = NULL;
static hw2secws_stats_t g_stats = {
    .accepted_packets = 0,
    .dropped_packets = 0,
};
static bool_t g_has_sysfs_device = FALSE;

static DEVICE_ATTR(stats_accepted_dropped, S_IWUSR | S_IRUGO , display, modify); 


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
static void
log_accept(void)
{
    ++g_stats.accepted_packets;
    printk(KERN_INFO "*** Packet Accepted ***\n");
}

static void
log_drop(void)
{
    ++g_stats.dropped_packets;
    printk(KERN_INFO "*** Packet Dropped ***\n");
}

static unsigned int
hw2secws_hookfn_accept(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
){
    UNUSED_ARG(priv);
    UNUSED_ARG(skb);
    UNUSED_ARG(state);

    log_accept();

    return NF_ACCEPT;
}

static unsigned int
hw2secws_hookfn_drop(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
){
    UNUSED_ARG(priv);
    UNUSED_ARG(skb);
    UNUSED_ARG(state);

    log_drop();

    return NF_DROP;
}

static inline void
zero_counters(void)
{
    g_stats.accepting
    (void)memset(&g_stats, 0, sizeof(g_stats));;
    printk(KERN_INFO "zero_counters, accepted=%lu dropped=%lu\n", (unsigned long)g_stats.accepted_packets, (unsigned long)g_stats.dropped_packets);
}

static int
register_hooks(void)
{
    int result = 0;
    int result_register_hook = -1;

    /* 1. Zero counters */
    zero_counters();

    /* 2. Register *INPUT* hook that *accepts* all the packets */
    /* 2.1. Init struct fields */
    g_input_hook.hook = hw2secws_hookfn_accept;
    g_input_hook.hooknum = NF_INET_LOCAL_IN;
    g_input_hook.pf = PF_INET;
    g_input_hook.priority = NF_IP_PRI_FIRST;

    /* 2.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_input_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }

    /* 3. Register *OUTPUT* hook that *accepts* all the packets */
    /* 3.1. Init struct fields */
    g_output_hook.hook = hw2secws_hookfn_accept;
    g_output_hook.hooknum = NF_INET_LOCAL_OUT;
    g_output_hook.pf = PF_INET;
    g_output_hook.priority = NF_IP_PRI_FIRST;

    /* 3.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_output_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }
        
    /* 4. Register *FORWARD* hook that *drops* all the packets */
    /* 4.1. Init struct fields */
    g_forward_hook.hook = hw2secws_hookfn_drop;
    g_forward_hook.hooknum = NF_INET_FORWARD;
    g_forward_hook.pf = PF_INET;
    g_forward_hook.priority = NF_IP_PRI_FIRST;

    /* 4.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_forward_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }


    /* Success */
    result = 0;
l_cleanup:
    if (0 != result) {
        unregister_hooks();
    }

    return result;
}

static int
init_device(void)
{
    int result = 0;
    int result_device_create_file = -1;

    /* 1. Create character device */
    g_major_number = register_chrdev(0, CHAR_DEVICE_NAME, &g_file_operations);
    if (0 > g_major_number) {
        result = -1;
        goto l_cleanup;
    }

    /* 2. Create sysfs class */
    g_hw2secws_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(g_hw2secws_class)) {
        result = -1;
        goto l_cleanup;
    }
        
    /* 3. Create sysfs device */
    g_hw2secws_device = device_create(g_hw2secws_class, NULL, MKDEV(g_major_number, 0), NULL, SYSFS_DEVICE_NAME);
    if (IS_ERR(g_hw2secws_class)) {
        result = -1;
        goto l_cleanup;
    }
    g_has_sysfs_device = TRUE;

    /* 4. Create sysfs file attributes */
    result_device_create_file = device_create_file(
        g_hw2secws_device,
        (const struct device_attribute *)&dev_attr_stats_accepted_dropped.attr
    );
    if (0 != result_device_create_file) {
        result = -1;
        goto l_cleanup;
    }
        
    /* Success */
    result = 0;
l_cleanup:
    if (0 != result) {
        clean_device();
    }

	return result;
}

static void
clean_device(void)
{
    if (NULL != g_hw2secws_device) {
        device_remove_file(g_hw2secws_device, (const struct device_attribute *)&dev_attr_stats_accepted_dropped.attr);
        g_hw2secws_device = NULL;
    }
    if (TRUE == g_has_sysfs_device) {
        device_destroy(g_hw2secws_class, MKDEV(g_major_number, 0));
        g_has_sysfs_device = FALSE;
    }

    if (NULL != g_hw2secws_class) {
        class_destroy(g_hw2secws_class);
        g_hw2secws_class = NULL;
    }

    if (INVALID_MAJOR_NUMBER != g_major_number) {
        unregister_chrdev(g_major_number, CHAR_DEVICE_NAME);
        g_major_number = INVALID_MAJOR_NUMBER;
    }
}

static void
unregister_hooks(void)
{
    nf_unregister_net_hook(&init_net, &g_input_hook);
    nf_unregister_net_hook(&init_net, &g_output_hook);
    nf_unregister_net_hook(&init_net, &g_forward_hook);
}


static ssize_t
display(struct device *dev, struct device_attribute *attr, char *buf)
{
    int result_scnprintf = -1;

    UNUSED_ARG(dev);
    UNUSED_ARG(attr);

    result_scnprintf = scnprintf(buf, PAGE_SIZE, "%lu,%lu\n", (unsigned long)g_stats.accepted_packets,
                                 (unsigned long)g_stats.dropped_packets);

    return result_scnprintf;
}

static ssize_t
modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    ssize_t result = 0;

    if (0 == count) {
        goto l_cleanup;
    }

    if ('0' == buf[0]) {
        zero_counters();
        result = count;
    }

l_cleanup:

    return result;
}

static int
__init hw2secws_init(void)
{
    int result = -1;

    /* 1. Register hooks */
    result = register_hooks();
    if (0 != result) {
        goto l_cleanup;
    }

    /* 2. Init char device and sysfs device */
    result = init_device();
    if (0 != result) {
        goto l_cleanup;
    }

    result = 0;
l_cleanup:
    if (0 != result) {
        clean_device();
        unregister_hooks();
    }

    return result;
}

static void __exit
hw2secws_exit(void)
{
    /* 1. Release device class file, class and character device */
    clean_device();

    /* 2. Release all the hooks */
    unregister_hooks();
}


/*   K E R N E L   H O O K S   */
module_init(hw2secws_init);
module_exit(hw2secws_exit);

