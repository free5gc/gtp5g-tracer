#include "gtp5g_tracer_kern.h"

// Struct definitions for GTP header access
struct gtp1_header
{
    __u8 flags;
    __u8 type;
    __u16 length;
    __u32 teid;
};

// downlink entrypoint
SEC("fentry/gtp5g_xmit_skb_ipv4")
int BPF_PROG(gtp5g_xmit_skb_ipv4_entry, struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    __u16 skb_len = 0;
    __u64 ts = bpf_ktime_get_ns();

    // Log device first for better readability
    if (skb && skb->dev)
    {
        bpf_printk("fentry/gtp5g_xmit_skb_ipv4: DEV=%s", skb->dev->name);
    }

    // Get packet length and other details
    if (skb)
    {
        skb_len = skb->len;
        bpf_printk("fentry/gtp5g_xmit_skb_ipv4: LEN=%u, TS=%llu", skb_len, ts);

        // We can't directly access TEID from pktinfo in this context
        // but we can check if pktinfo exists and log it
        if (pktinfo)
        {
            bpf_printk("fentry/gtp5g_xmit_skb_ipv4: pktinfo exists");
        }
    }

    bpf_printk("fentry/gtp5g_xmit_skb_ipv4: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    return 0;
}

SEC("fexit/gtp5g_xmit_skb_ipv4")
int BPF_PROG(gtp5g_xmit_skb_ipv4_exit, struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    __u16 skb_len = 0;
    __u64 ts = bpf_ktime_get_ns();

    // Log device first for better readability
    if (skb && skb->dev)
    {
        bpf_printk("fexit/gtp5g_xmit_skb_ipv4: DEV=%s", skb->dev->name);
    }

    // Get packet length
    if (skb)
    {
        skb_len = skb->len;
        bpf_printk("fexit/gtp5g_xmit_skb_ipv4: LEN=%u, TS=%llu", skb_len, ts);
    }

    bpf_printk("fexit/gtp5g_xmit_skb_ipv4: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    return 0;
}

// uplink entrypoint
SEC("fentry/gtp5g_encap_recv")
int BPF_PROG(gtp5g_encap_recv_entry, struct sock *sk, struct sk_buff *skb)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    __u16 skb_len = 0;

    // Get packet length and device info
    if (skb)
    {
        skb_len = skb->len;

        // Access device name only when skb is valid
        if (skb->dev)
        {
            bpf_printk("fentry/gtp5g_encap_recv: DEV=%s", skb->dev->name);
        }

        // Check if it's a GTP packet
        if (skb->len >= 8)
        {
            bpf_printk("fentry/gtp5g_encap_recv: GTP packet detected (len >= 8)");
        }
    }
    else
    {
        bpf_printk("fentry/gtp5g_encap_recv: skb is NULL");
    }

    bpf_printk("fentry/gtp5g_encap_recv: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    bpf_printk("fentry/gtp5g_encap_recv: LEN=%u", skb_len);
    return 0;
}

SEC("fexit/gtp5g_encap_recv")
int BPF_PROG(gtp5g_encap_recv_exit, struct sock *sk, struct sk_buff *skb)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();

    bpf_printk("fexit/gtp5g_encap_recv: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    bpf_printk("fexit/gtp5g_encap_recv: DEV=%s", skb->dev->name);
    return 0;
}

// Additional packet handling functions
SEC("fentry/gtp5g_handle_skb_ipv4")
int BPF_PROG(gtp5g_handle_skb_ipv4_entry, struct sk_buff *skb)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();

    bpf_printk("fentry/gtp5g_handle_skb_ipv4: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    if (skb && skb->dev)
    {
        bpf_printk("fentry/gtp5g_handle_skb_ipv4: DEV=%s", skb->dev->name);
    }
    return 0;
}

SEC("fexit/gtp5g_handle_skb_ipv4")
int BPF_PROG(gtp5g_handle_skb_ipv4_exit, struct sk_buff *skb, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u16 skb_len = 0;
    __u64 ts = bpf_ktime_get_ns();

    // Get packet length if available
    if (skb)
    {
        skb_len = skb->len;
        bpf_printk("fexit/gtp5g_handle_skb_ipv4: LEN=%u, TS=%llu", skb_len, ts);
    }

    // Print return value in hex format for better readability
    bpf_printk("fexit/gtp5g_handle_skb_ipv4: PID=%u, TGID=%u, RET=0x%x (skb ptr)", pid, tgid, ret);
    return 0;
}

// GTP header manipulation
SEC("fentry/gtp5g_push_header")
int BPF_PROG(gtp5g_push_header_entry, struct sk_buff *skb)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u16 skb_len = 0;

    // Get packet length
    if (skb)
    {
        skb_len = skb->len;
    }

    bpf_printk("fentry/gtp5g_push_header: PID=%u, TGID=%u, LEN=%u", pid, tgid, skb_len);
    if (skb && skb->dev)
    {
        bpf_printk("fentry/gtp5g_push_header: DEV=%s", skb->dev->name);
    }
    return 0;
}

SEC("fexit/gtp5g_push_header")
int BPF_PROG(gtp5g_push_header_exit, struct sk_buff *skb, int ret)
{
    __u16 skb_len = 0;
    __u64 ts = bpf_ktime_get_ns();

    // Get packet length after header addition
    if (skb)
    {
        skb_len = skb->len;
    }

    // Print return value in hex format for better readability
    bpf_printk("fexit/gtp5g_push_header: RET=0x%x (skb ptr), LEN=%u, TS=%llu", ret, skb_len, ts);
    return 0;
}

// PDR matching functions
SEC("fentry/pdr_find_by_gtp1u")
int BPF_PROG(pdr_find_by_gtp1u_entry)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;

    bpf_printk("fentry/pdr_find_by_gtp1u: PID=%u, TGID=%u", pid, tgid);
    return 0;
}

SEC("fexit/pdr_find_by_gtp1u")
int BPF_PROG(pdr_find_by_gtp1u_exit, void *ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;

    // If ret is NULL, no PDR was found
    if (ret == NULL)
    {
        bpf_printk("fexit/pdr_find_by_gtp1u: PID=%u, PDR=Not Found", pid);
    }
    else
    {
        bpf_printk("fexit/pdr_find_by_gtp1u: PID=%u, PDR=Found", pid);
    }
    return 0;
}

// QoS enforcement
SEC("fentry/policePacket")
int BPF_PROG(policePacket_entry)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();

    bpf_printk("fentry/policePacket: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    return 0;
}

// IP routing function
SEC("fentry/ip4_find_route")
int BPF_PROG(ip4_find_route_entry)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();

    bpf_printk("fentry/ip4_find_route: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    return 0;
}

SEC("fexit/ip4_find_route")
int BPF_PROG(ip4_find_route_exit, void *ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;

    // If ret is NULL, route was not found
    if (ret == NULL)
    {
        bpf_printk("fexit/ip4_find_route: PID=%u, Route=Not Found", pid);
    }
    else
    {
        bpf_printk("fexit/ip4_find_route: PID=%u, Route=Found", pid);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
