#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/inet.h>

int ipfilter(struct xdp_md *ctx) { 
bpf_trace_printk("Got a Packet !");
void *data = (void *)(long)ctx->data; 
void *data_end = (void *)(long)ctx->data_end; 
struct ethhdr *eth = data; 

if ((void *)eth + sizeof(*eth) <= data_end) 
  {     
    struct iphdr *iph = data + sizeof(*eth); 
    if ((void *)iph + sizeof(*iph) <= data_end) {
      
      if(iph->saddr == 16777343) { 
          bpf_trace_printk("Dropped the Packet form IP : %pI4" , &iph->saddr);
	  return XDP_DROP; 
      } 

    } 
  } 
  return XDP_PASS; 
}
