#include "gtp5g_tracer_kern.h"

// downlink entrypoint
SEC("fentry/gtp5g_xmit_skb_ipv4")
int BPF_PROG(gtp5g_xmit_skb_ipv4_entry, struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    
    bpf_printk("fentry/gtp5g_xmit_skb_ipv4: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    bpf_printk("fentry/gtp5g_xmit_skb_ipv4: DEV=%s", skb->dev->name);
    return 0;
}

SEC("fexit/gtp5g_xmit_skb_ipv4")
int BPF_PROG(gtp5g_xmit_skb_ipv4_exit, struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    
    bpf_printk("fexit/gtp5g_xmit_skb_ipv4: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    bpf_printk("fexit/gtp5g_xmit_skb_ipv4: DEV=%s", skb->dev->name);
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
    
    bpf_printk("fentry/gtp5g_encap_recv: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    bpf_printk("fentry/gtp5g_encap_recv: DEV=%s", skb->dev->name);
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

char _license[] SEC("license") = "GPL";
