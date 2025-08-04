#include "gtp5g_tracer_kern.h"

// downlink entrypoint
SEC("fentry/gtp5g_xmit_skb_ipv4")
int BPF_PROG(gtp5g_xmit_skb_ipv4, struct sk_buff *skb, struct gtp5g_pktinfo *pktinfo)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    
    bpf_printk("gtp5g_xmit_skb_ipv4: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    return 0;
}

// uplink entrypoint
SEC("fentry/gtp5g_encap_recv")
int BPF_PROG(gtp5g_encap_recv, struct sock *sk, struct sk_buff *skb)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;
    __u32 cpu = bpf_get_smp_processor_id();
    
    bpf_printk("gtp5g_encap_recv: PID=%u, TGID=%u, CPU=%u", pid, tgid, cpu);
    return 0;
}

char _license[] SEC("license") = "GPL";
