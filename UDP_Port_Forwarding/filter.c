#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
int udpfilter(struct xdp_md *ctx) { 
bpf_trace_printk("got a packet");
void *data = (void *)(long)ctx->data; 
void *data_end = (void *)(long)ctx->data_end; 
struct ethhdr *eth = data; 

if ((void *)eth + sizeof(*eth) <= data_end) 
  {     
    struct iphdr *iph = data + sizeof(*eth); 
    if ((void *)iph + sizeof(*iph) <= data_end) {

      bpf_trace_printk("%pI4" , &iph->daddr); 
      
      if(iph->protocol == IPPROTO_UDP) { 
        struct udphdr *udp = (void *)iph + sizeof(*iph); 
        if ((void *)udp + sizeof(*udp) <= data_end) { 
           if(udp->dest == ntohs(3344)) {
            bpf_trace_printk("Port Changed !"); 
            udp->dest = ntohs(5566); 
            } 
          } 
        } 
      } 
    } 
  return XDP_PASS; 
}
