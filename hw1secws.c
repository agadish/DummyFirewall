/**
 * @file hw1secws.c
 * @author Assaf Gadish
 *
 * @brief A dummy firewall. Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "common.h"


/*   M A C R O S   */
MODULE_LICENSE("GPL");


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static int __init hw1secws_init(void);

static void __exit hw1secws_exit(void);

/**
 * @brief Print a kernel message that indicates a packet was accepted
 */
static void log_accept(void);

/**
 * @brief Print a kernel message that indicates a packet was dropped
 */
static void log_drop(void);

/**
 * @brief A netfilter hook handler that always accepts the given packet
 * 
 * @param[in] priv Ignored
 * @param[in] skb The packet's socket buffer (ignored)
 * @param[in] state The packet's netfilter hook state (ignored)
 *
 * @return NF_ACCEPT
 */
static unsigned int hw1secws_hookfn_accept(
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
static unsigned int hw1secws_hookfn_drop(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
);


/*   G L O B A L S   */
/** 
 * @brief Netfilter hook for INPUT packet chain, aka packets destinated to this machine
 */
static struct nf_hook_ops g_input_hook;

/** 
 * @brief Netfilter hook for OUTPUT packet chain, aka packets sent by this machine
 */
static struct nf_hook_ops g_input_hook;

/** 
 * @brief Netfilter hook for FORWARD packet chain, aka packets that are neither destinated to this
 *        machine nor sent by this machine
 */
static struct nf_hook_ops g_forward_hook;


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
static void log_accept(void)
{
    printk(KERN_INFO "*** Packet Accepted ***\n");
}

static void log_drop(void)
{
    printk(KERN_INFO "*** Packet Dropped ***\n");
}

static unsigned int hw1secws_hookfn_accept(
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

static unsigned int hw1secws_hookfn_drop(
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

static int __init hw1secws_init(void)
{
    int result = 0;
    int result_register_hook = -1;

    /* 1. Register *INPUT* hook that *accepts* all the packets */
    /* 1.1. Init struct fields */
    g_input_hook.hook = hw1secws_hookfn_accept;
    g_input_hook.hooknum = NF_INET_LOCAL_IN;
    g_input_hook.pf = PF_INET;
    g_input_hook.priority = NF_IP_PRI_FIRST;

    /* 1.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_input_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }

    /* 2. Register *OUTPUT* hook that *accepts* all the packets */
    /* 2.1. Init struct fields */
    g_input_hook.hook = hw1secws_hookfn_accept;
    g_input_hook.hooknum = NF_INET_LOCAL_OUT;
    g_input_hook.pf = PF_INET;
    g_input_hook.priority = NF_IP_PRI_FIRST;

    /* 2.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_output_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }
        
        
    /* 3. Register *FORWARD* hook that *drops* all the packets */
    /* 3.1. Init struct fields */
    g_forward_hook.hook = hw1secws_hookfn_drop;
    g_forward_hook.hooknum = NF_INET_FORWARD;
    g_forward_hook.pf = PF_INET;
    g_forward_hook.priority = NF_IP_PRI_FIRST;

    /* 3.2. Register hook */
    result_register_hook = nf_register_net_hook(&init_net, &g_forward_hook);
    if (0 != result_register_hook) {
        result = result_register_hook;
        goto l_cleanup;
    }
        
    /* Success */
    result = 0;
l_cleanup:

	return result;
}

static void __exit hw1secws_exit(void)
{
    /* Release all the hooks which were registed by hw1secws_init */
    nf_unregister_net_hook(&init_net, &g_input_hook);
    nf_unregister_net_hook(&init_net, &g_output_hook);
    nf_unregister_net_hook(&init_net, &g_forward_hook);
}


/*   K E R N E L   H O O K S   */
module_init(hw1secws_init);
module_exit(hw1secws_exit);

