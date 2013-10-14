/* 
 * File:   isis_pduauth.h
 * Author: hareendrachamara
 *
 * Created on October 5, 2013, 9:59 AM
 */
#include<stdio.h>

#include <zebra.h>

#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "log.h"
#include "stream.h"
#include "vty.h"
#include "hash.h"
#include "prefix.h"
#include "if.h"
#include "checksum.h"
#include "md5.h"

#include "dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_network.h"
#include "isis_misc.h"
#include "isis_dr.h"
#include "isis_tlv.h"
#include "isisd.h"
#include "isis_dynhn.h"
#include "isis_lsp.h"
#include "isis_auth.h"
#include "iso_checksum.h"
#include "isis_csm.h"
#include "isis_events.h"

#define ISIS_MIN_FXD_HDRLEN 15
#define ISIS_MIN_PDULEN 13

/*PNBBY may be defined in other files*/
#ifndef PNBBY
#define PNBBY 8
#endif 

/*utility mask array*/
static u_int8_t maskbit[]={ 
    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8,0xfc, 0xfe, 0xff
};

/*Compare Two area addresses*/
int area_address_compare(struct list *pack1, struct list *pack2)
{
    struct area_addr *address1, *address2;
    struct listnode *node1,*node2;
    
   for(ALL_LIST_ELEMENTS_RO(pack1,node1,address1))
   {
    for(ALL_LIST_ELEMENTS_RO(pack2,node2,address2))
    {
        
     if(address1->addr_len == address2->addr_len && 
      !memcmp(address1->area_addr, address2->area_addr,(int)address1->addr_len))
     {
       return 1;
     }
    }
   }
    
    return 0;
}

/*
 * from =>Prefix.c:prefix_match()
 * ip_a => the Intermediate System interface ip address structure
 * ip_b => the ISIS Hello senders ip address
 * return  0     the ip_b ip is not in the same subnet as ip_a       
 *         1     the ip_b ip is in the same subnet as ip_a
 */

int ip_prefix_match(struct prefix_ipv4 *ip_a,struct in_addr *ip_b)
{
  u_int8_t *adrs_a, *adrs_b;
  int shift, offset, offsetloop,len;
 
  adrs_a = (u_char *) & ip_a->prefix.s_addr;
  adrs_b = (u_char *) & ip_b->s_addr;
  len = ip_a->prefixlen;

  shift = len % PNBBY;
  offsetloop = offset = len / PNBBY;

  while (offsetloop--)
    if (adrs_a[offsetloop] != adrs_b[offsetloop])
      return 0;

  if (shift)
    if (maskbit[shift] & (adrs_a[offset] ^ adrs_b[offset]))
      return 0;

  return 1;
}

/*
 * Compares two set of ip addresses
 * param list_a    the local interface's ip addresses
 * param list_b    the iih interface's ip address
 * return         0   no match;
 *                1   match;
 */
int ip_match (struct list *list_a, struct list *list_b)
{
  struct prefix_ipv4 *ip_a;
  struct in_addr *ip_b;
  struct listnode *node_a, *node_b;

  if ((list_a == NULL) || (list_b == NULL))
    return 0;
  
  for (ALL_LIST_ELEMENTS_RO (list_a, node_a, ip_a))
  {
    for (ALL_LIST_ELEMENTS_RO (list_b, node_b, ip_b))
    {
      if (ip_prefix_match (ip_a, ip_b))
	{
	  return 1;		/* match */
	}
    }

  }
  return 0;
}

/*Accept a PDU of a given level*/
int accept_pdu_level(int circuit_t, int level)
{
    int return_v;

    return_v = (circuit_t == level);

    return return_v;
}

/*Verify authentication information. 
 HMAC-MD5 will be implemented
 *Recive accepting procedure is implemented here.
 */

int authenticate_pdu(struct isis_passwd *external,struct isis_passwd
*local,struct stream *stream, uint32_t auth_tlv_offset)
{
    unsigned char digest[ISIS_AUTH_MD5_SIZE];
    
    if(local->type != external->type)
        return ISIS_ERROR;
    
    switch(local->type)
    {
    
        case ISIS_PASSWD_TYPE_UNUSED:
            //do the respective operation
            break;
        case ISIS_PASSWD_TYPE_CLEARTXT:
            //do the respective operation
            break;
            
        case ISIS_PASSWD_TYPE_HMAC_MD5:
            if(external->len != ISIS_AUTH_MD5_SIZE)
                return ISIS_ERROR;
            
            memset(STREAM_DATA (stream)+auth_tlv_offset+3, 0, 
                    ISIS_AUTH_MD5_SIZE);
            hmac_md5(STREAM_DATA(stream),stream_get_endp(stream),
                    (unsigned char*)&(local->passwd), local->len, 
                    (caddr_t)&digest);
            memcpy(STREAM_DATA (stream)+auth_tlv_offset+3,
                    external->passwd,ISIS_AUTH_MD5_SIZE);
            
            return memcmp(digest,external->passwd,ISIS_AUTH_MD5_SIZE);            
        case ISIS_PASSWD_TYPE_PRIVATE:
            //do the operation
            break;
            
        default:
            zlog_err("Authentication type is unrecognized.");
            return ISIS_ERROR;
    
    }
    /*If authentication is not enabled pass the PDU*/
    return ISIS_OK;

}
/**/
/*
 * Calculate the length of Authentication Info. TLV.
 */
uint16_t auth_tlv_length (int level, struct isis_circuit *circuit)
{
  struct isis_passwd *passwd;
  uint16_t length;

  if (level == IS_LEVEL_1)
    passwd = &circuit->area->area_passwd;
  else
    passwd = &circuit->area->domain_passwd;

  /* Also include the length of TLV header */
  length = AUTH_INFO_HDRLEN;
  if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
  {
    switch (passwd->type)
    {
      /* Cleartext */
      case ISIS_PASSWD_TYPE_CLEARTXT:
        //assign the value
        break;

        /* HMAC MD5 */
      case ISIS_PASSWD_TYPE_HMAC_MD5:
        length += ISIS_AUTH_MD5_SIZE;
        break;

      default:
        break;
    }
  }

  return length;
}
/**/




