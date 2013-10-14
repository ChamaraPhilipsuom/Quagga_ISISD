#include<stdio.h>
#include <zebra.h>

#include "lib/linklist.h"
#include "lib/memory.h"
#include "lib/thread.h"
#include "lib/log.h"
#include "lib/stream.h"
#include "lib/vty.h"
#include "lib/hash.h"
#include "lib/prefix.h"
#include "lib/if.h"
#include "lib/checksum.h"
#include "lib/md5.h"
#include "lib/memtypes.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_auth_test.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pduauth.h"
#include "isisd/iso_checksum.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"


/*Variables*/
struct listnode* list_1_nodes[MAXARRAYSIZE];
struct listnode* list_2_nodes[MAXARRAYSIZE];   
struct list *checklist_1;
struct list *checklist_2;
/*addreses*/
struct area_addr* list1_area_addrs[MAXARRAYSIZE];
struct area_addr* list2_area_addrs[MAXARRAYSIZE];
struct prefix_ipv4 *ip_a;
struct prefix_ipv4 *ip_b;
 /*End Of Variables*/     
int main(){

int arg = ARGDEFAULT;
init_struct_list(0,0);
/*Test Cases for function 
 * area_address_compare(struct list *pack1, struct list *pack2)*/
arg = test_equal_area_set_ret1();
if(arg!=ARGDEFAULT){
    if(arg==1)
        printf("%stest_equal_area_set_ret1 passed.\n",KGRN);
    
    else{
        printf("%stest_equal_area_set_ret1 failed. Returned %d",KRED,arg);
        return 0;
    }
}
arg = ARGDEFAULT;
arg = test_difsize_difareaset_ret0();
if(arg!=ARGDEFAULT){
    if(arg==0)
        printf("%stest_deif_area_set_ret0 passed.\n",KGRN);
    
    else{
        printf("%stest_deif_area_set_ret0 failed. Returned %d",KRED,arg);
        return 0;
    }
}
arg = ARGDEFAULT;
arg = test_equalsize_difadrsset_equaladdrlength_ret0();
if(arg!=ARGDEFAULT){
    if(arg==0)
        printf("%stest_equalsize_difadrsset_ret0 passed.\n",KGRN);
    
    else{
        printf("%stest_equalsize_difadrsset_ret0 failed. Returned %d",KRED,arg);
        return 0;
    }
}
arg = ARGDEFAULT;
arg = test_equalsize_difadrsset_difaddrlength_ret0();
if(arg!=ARGDEFAULT)
{
    if(arg==0)
        printf("%stest_difaddrlength_ret0 passed.\n",KGRN);
    
    else{
        printf("%stest_difaddrlength_ret0 failed. Returned %d",KRED,arg);
        return 0;
    }
}

arg = ARGDEFAULT;
arg = test_equalsize_equaladrsset_difaddrlength_ret1();
if(arg!=ARGDEFAULT)
{
     if(arg==1)
        printf("%stest_equalsize_equaladrsset_difaddrlength_ret1 passed.\n",KGRN);
    
    else{
        printf("%stest_equalsize_equaladrsset_difaddrlength_ret1 failed. Returned %d",KRED,arg);
        return 0;
    }


}

/*Enf of Test Cases for 
 * area_address_compare(struct list *pack1, struct list *pack2)*/
    
    return 0;
}
/*Nullify every pointer for the next test*/
int init_struct_list(int list1_size, int list2_size)
{
    int i=0;
    /*Variables*/
    /*List 1*/
    for(i=0;i<MAXARRAYSIZE ; i++)
    {
        if(list_1_nodes[i]!=NULL)
        {
           XFREE(MTYPE_LINK_NODE,list_1_nodes[i]);
        }
    
    }
    for(i=0; i<list1_size ; i++)
    {
        list_1_nodes[i] = XMALLOC
                (MTYPE_LINK_NODE,sizeof(struct listnode));
    
    }
    /*List 2*/
    for(i=0;i<MAXARRAYSIZE ; i++)
    {
        if(list_2_nodes[i]!=NULL)
        {
            XFREE(MTYPE_LINK_NODE,list_2_nodes[i]);
        }
    
    }
    for(i=0; i<list2_size ; i++)
    {
        list_2_nodes[i] = XMALLOC
                (MTYPE_LINK_NODE,sizeof(struct listnode));
    
    } 
    /*Form the lists*/
    /*List 1*/
    for(i =0 ; i<list1_size ; i++)
    {
        if(i==0)
        {
            list_1_nodes[i]-> prev = NULL;
            list_1_nodes[i]->next = list_1_nodes[i+1];
            list_1_nodes[i]->data = NULL;
        }
        else if(i==list1_size-1)
        {
            list_1_nodes[i]-> prev = list_1_nodes[i-1];
            list_1_nodes[i]->next = NULL;
            list_1_nodes[i]->data = NULL;
        }
        else
        {
            list_1_nodes[i]-> prev = list_1_nodes[i-1];
            list_1_nodes[i]->next =  list_1_nodes[i+1];
        }
    
    }
    
    /*List 2*/
    for(i = 0; i<list2_size ; i++)
    {
        if(i==0)
        {
            list_2_nodes[i] -> prev = NULL;
            list_2_nodes[i] -> next = list_2_nodes[i+1];
            list_2_nodes[i] -> data = NULL;
        }
        else if(i==list2_size-1)
        {
            list_2_nodes[i] -> prev = list_2_nodes[i-1];
            list_2_nodes[i] -> next = NULL;
            list_2_nodes[i] -> data = NULL;
        }
        else
        {
            list_2_nodes[i] -> prev = list_2_nodes[i-1];
            list_2_nodes[i] -> next = list_2_nodes[i+1];
        }    
    }   
    /*free lists*/
    if(checklist_1!=NULL)
        XFREE(MTYPE_LINK_LIST,checklist_1);
        
    if(checklist_2!=NULL)
        XFREE(MTYPE_LINK_LIST,checklist_2);
    
    /*Make Listss*/
    if(list1_size>0)
    {
        checklist_1->head = list_1_nodes[0];
        checklist_1->tail = list_1_nodes[list1_size-1];
        checklist_1->count = list1_size;
    }
    
    if(list2_size>0)
    {
        checklist_2 -> head = list_2_nodes[0];
        checklist_2 -> tail = list_2_nodes[list2_size-1];
        checklist_2->count = list2_size;
    }
    return SUCCESS;
}

/*this is like strncpy(dest,source,length)
 additionally sets the area_addr->addr_len value*/
int copy_area_address(struct area_addr* addr, u_char* name, int length)
{
    int i = 0;
    addr->addr_len=length;
    for(i=0;i<length;i++)
    {
        
        *((addr->area_addr)+i)=*(name+i);
    }
    return SUCCESS;
}
int test_equal_area_set_ret1()
{
    int list1_size,list2_size;
    list1_size=4;
    list2_size=4;
    init_struct_list(list1_size,list2_size);
    int i=0;
    u_char* test_add_list[4];   
    struct area_addr* addlist[4];
    
    for(i=0;i<4;i++)
    {
        addlist[i] = XMALLOC(MTYPE_ISIS_TMP,sizeof(struct area_addr));
    }   
   
   
    test_add_list[0] = "L2BB";
    test_add_list[1] = "L2CC";
    test_add_list[2] = "L2BB";
    test_add_list[3] = "L2CC";
    
    for(i=0; i< 4;i++)
    {
        copy_area_address(addlist[i],test_add_list[i],4);
    }
    int j=0;
    for(i=0; i<list1_size ; i++)
    {
        if(i!=0 && i!=list1_size-1)
        {
        list_1_nodes[i]->data=addlist[j];
        j++;
        }
    }
    for(i=0; i< list2_size ; i++)
    {
        if(i!=0 && i!=list2_size-1)
        {
        list_2_nodes[i]->data = addlist[j];
        j++;
        }
    
    }
    
    /*Free addlist*/
     for(i=0;i<4;i++)
    {
        XFREE (MTYPE_ISIS_TMP,addlist[i]);
    }
    /*Call for the function*/
    return area_address_compare(checklist_1,checklist_2);
}
int test_difsize_difareaset_ret0()
{
    int list1_size,list2_size;
    list1_size=4;
    list2_size=5;
    init_struct_list(list1_size,list2_size);
    int i=0;
    u_char* test_add_list[5];   
    struct area_addr* addlist[5];
    
    for(i=0;i<5;i++)
    {
        addlist[i] = XMALLOC(MTYPE_ISIS_TMP,sizeof(struct area_addr));
    }   
   
   
    test_add_list[0] = "L2BB";
    test_add_list[1] = "L2CC";
    test_add_list[2] = "L2BC";
    test_add_list[3] = "L2CC";
    test_add_list[4] = "L3BB";
    
    for(i=0; i< 5;i++)
    {
        copy_area_address(addlist[i],test_add_list[i],4);
    }
    int j=0;
    for(i=0; i<list1_size ; i++)
    {
        if(i!=0 && i!=list1_size-1)
        {
        list_1_nodes[i]->data=addlist[j];
        j++;
        }
    }
    for(i=0; i< list2_size ; i++)
    {
        if(i!=0 && i!=list2_size-1)
        {
        list_2_nodes[i]->data = addlist[j];
        j++;
        }
    
    }
    
    /*Free addlist*/
     for(i=0;i<4;i++)
    {
        XFREE (MTYPE_ISIS_TMP,addlist[i]);
    }
    /*Call for the function*/
    return area_address_compare(checklist_1,checklist_2);

    
}
int test_equalsize_difadrsset_equaladdrlength_ret0()
{
    int list1_size,list2_size;
    list1_size=4;
    list2_size=4;
    init_struct_list(list1_size,list2_size);
    int i=0;
    u_char* test_add_list[4];   
    struct area_addr* addlist[4];
    
    for(i=0;i<4;i++)
    {
        addlist[i] = XMALLOC(MTYPE_ISIS_TMP,sizeof(struct area_addr));
    }   
   
   
    test_add_list[0] = "L2BB";
    test_add_list[1] = "L2CC";
    test_add_list[2] = "L2BD";
    test_add_list[3] = "L2CC";
    
    for(i=0; i< 4;i++)
    {
        copy_area_address(addlist[i],test_add_list[i],4);
    }
    int j=0;
    for(i=0; i<list1_size ; i++)
    {
        if(i!=0 && i!=list1_size-1)
        {
        list_1_nodes[i]->data=addlist[j];
        j++;
        }
    }
    for(i=0; i< list2_size ; i++)
    {
        if(i!=0 && i!=list2_size-1)
        {
        list_2_nodes[i]->data = addlist[j];
        j++;
        }
    
    }
    
    /*Free addlist*/
     for(i=0;i<4;i++)
    {
        XFREE (MTYPE_ISIS_TMP,addlist[i]);
    }
    /*Call for the function*/
    return area_address_compare(checklist_1,checklist_2);
}
int test_equalsize_difadrsset_difaddrlength_ret0()
{
    int list1_size,list2_size;
    list1_size=4;
    list2_size=4;
    init_struct_list(list1_size,list2_size);
    int i=0;
    u_char* test_add_list[4];   
    struct area_addr* addlist[4];
    
    for(i=0;i<4;i++)
    {
        addlist[i] = XMALLOC(MTYPE_ISIS_TMP,sizeof(struct area_addr));
    }   
   
   
    test_add_list[0] = "L2BB";
    test_add_list[1] = "L2CCD";
    test_add_list[2] = "L2BD";
    test_add_list[3] = "L2ACD";
    
    
        copy_area_address(addlist[0],test_add_list[0],4);
        copy_area_address(addlist[1],test_add_list[1],5);
        copy_area_address(addlist[2],test_add_list[2],4);
        copy_area_address(addlist[3],test_add_list[3],5);
    
    int j=0;
    for(i=0; i<list1_size ; i++)
    {
        if(i!=0 && i!=list1_size-1)
        {
        list_1_nodes[i]->data=addlist[j];
        j++;
        }
    }
    for(i=0; i< list2_size ; i++)
    {
        if(i!=0 && i!=list2_size-1)
        {
        list_2_nodes[i]->data = addlist[j];
        j++;
        }
    
    }    
    /*Free addlist*/
     for(i=0;i<4;i++)
    {
        XFREE (MTYPE_ISIS_TMP,addlist[i]);
    }
    /*Call for the function*/
    return area_address_compare(checklist_1,checklist_2);
}
int test_equalsize_equaladrsset_difaddrlength_ret1()
{
     int list1_size,list2_size;
    list1_size=4;
    list2_size=4;
    init_struct_list(list1_size,list2_size);
    int i=0;
    u_char* test_add_list[4];   
    struct area_addr* addlist[4];
    
    for(i=0;i<4;i++)
    {
        addlist[i] = XMALLOC(MTYPE_ISIS_TMP,sizeof(struct area_addr));
    }   
   
   
    test_add_list[0] = "L2BB";
    test_add_list[1] = "L2CCD";
    test_add_list[2] = "L2BB";
    test_add_list[3] = "L2CCD";
    
    
        copy_area_address(addlist[0],test_add_list[0],4);
        copy_area_address(addlist[1],test_add_list[1],5);
        copy_area_address(addlist[2],test_add_list[2],4);
        copy_area_address(addlist[3],test_add_list[3],5);
    
    int j=0;
    for(i=0; i<list1_size ; i++)
    {
        if(i!=0 && i!=list1_size-1)
        {
        list_1_nodes[i]->data=addlist[j];
        j++;
        }
    }
    for(i=0; i< list2_size ; i++)
    {
        if(i!=0 && i!=list2_size-1)
        {
        list_2_nodes[i]->data = addlist[j];
        j++;
        }
    
    }    
    /*Free addlist*/
     for(i=0;i<4;i++)
    {
        XFREE (MTYPE_ISIS_TMP,addlist[i]);
    }
    /*Call for the function*/
    return area_address_compare(checklist_1,checklist_2);
}
