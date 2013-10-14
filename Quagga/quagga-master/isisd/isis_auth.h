/* 
 * File:   isis_pduauth.h
 * Author: hareendrachamara
 *
 * Created on October 2, 2013, 8:53 AM
 */

#ifndef ISIS_PDUAUTH_H
#define	ISIS_PDUAUTH_H






#ifdef __SUNPRO_C
#pragma pack(1)
#endif

#ifdef	__cplusplus
}
#endif

#ifndef ISIS_SYS_ID_LEN 
#define ISIS_SYS_ID_LEN  6
#endif

//ES-IS FIXED HEADER IS DOCUMENTED
#define ES_IS_FXD_HDR_LENGTH 9;

#define ESH_PDU              2   
#define ISH_PDU              4  
#define RD_PDU               5          

struct esis_fxd_hdr{
   
    u_int8_t irpd;// (intradomain routing protocol)
    u_int8_t length_indicator;
    u_int8_t ver_pro_id;//version or protocol id
    u_int8_t ver_pro_id_length;
    u_int8_t pdu_type;
    u_int16_t holdingtime;
    u_int16_t checksum;
};



#define ISIS_FXD_HDR_LENGTH 8;



struct isis_fxd_hdr{
    u_int8_t irpd;
    u_int8_t length_indicator;
    u_int8_t ver_pro_id;
    u_int8_t ver_pro_id_length;
    u_int8_t pdu_type;
    u_int8_t version;
    u_int8_t reserved;
    u_int8_t max_area_adrs;
};




/*IS-IS pdu types*/



// L1 and L2 LAN IS to IS Hello PDU header

#define L1_LAN_HELLO         15         
#define L2_LAN_HELLO         16    



struct isis_hello_pdu_hdr{

    u_int8_t circuit_type;
    u_int8_t src_id[ISIS_SYS_ID_LEN];
    u_int16_t holdingtime;
    u_int16_t pdulength;
    u_int8_t priority;
    u_int8_t lan_id[ISIS_SYS_ID_LEN+1];
};

#define ISIS_LANHELLO_HDRLEN 19

//Point-to-point IS to IS hello PDU header

#define P2P_HELLO 17





struct isis_p2p_hello_pdu_hdr{

    u_int8_t circuit_type;
    u_int8_t src_id[ISIS_SYS_ID_LEN];
    u_int16_t holdingtime;
    u_int16_t pdulength;
    u_int8_t localcircuit_id;

};
#define ISIS_P2PHELLO_HDRLEN 12


// L1 and L2 IS to IS link state PDU header
#define L1_LINK_STATE        18
#define L2_LINK_STATE        20

struct isis_lsp_hdr{

    u_int16_t pdulength;
    u_int16_t remain_lifetime;
    u_int8_t lsp_id[ISIS_SYS_ID_LEN+2];
    u_int32_t seqnc_num;
    u_int16_t checksum;
    u_int8_t link_state_bits;
};

#define ISIS_LSP_HDRLEN 19

/*
 * Since the length field of LSP Entries TLV is one byte long, and each LSP
 * entry is LSP_ENTRIES_LEN (16) bytes long, the maximum number of LSP entries
 * can be accomodated in a TLV is
 * 255 / 16 = 15.
 * 
 * Therefore, the maximum length of the LSP Entries TLV is
 * 16 * 15 + 2 (header) = 242 bytes.
 */

#define MAX_LSP_ENTRIES_TLV_SIZE 242

#define L1_COMPLETE_SEQNC_NUM  24
#define L2_COMPLETE_SEQNC_NUM  25




struct isis_complete_seqncnum_hdr{
    u_int16_t pdulength;
    u_int8_t src_id[ISIS_SYS_ID_LEN+1];
    u_int8_t start_lsp_id[ISIS_SYS_ID_LEN+2];
    u_int8_t end_lsp_id[ISIS_SYS_ID_LEN+2];


};
#define ISIS_CMPLTSEQNUM_HDRLEN 25

#define L1_PARTIAL_SEQNC_NUM   26
#define L2_PARTIAL_SEQNC_NUM   27         



struct isis_partial_seqncnuum_hdr{

    u_int16_t pdulength;
    u_int8_t src_id[ISIS_SYS_ID_LEN+1];

};
#define ISIS_PARTIALSEQNCNUM_HDRLEN 9


#ifdef __SUNPRO_C
#pragma pack()
#endif

/*Reciving functions for ISIS PDUS*/
int isis_receive (struct thread *thread);

/*
 * calling arguments for snp_process ()
 */
#define ISIS_SNP_PSNP_FLAG 0
#define ISIS_SNP_CSNP_FLAG 1

#define ISIS_AUTH_MD5_SIZE       16U

int area_address_compare(struct list *pack1, struct list *pack2);
int ip_prefix_match(struct prefix_ipv4 *ip_a,struct in_addr *ip_b);
int ip_match (struct list *list_a, struct list *list_b);
int accept_pdu_level(int circuit_t, int level);
int authenticate_pdu(struct isis_passwd *external,struct isis_passwd
*local,struct stream *stream, uint32_t auth_tlv_offset);
uint16_t auth_tlv_length (int level, struct isis_circuit *circuit);

/*
 * Sending functions
 */


#endif	/* ISIS_PDUAUTH_H */


