/* 
 * File:   isis_auth_test.h
 * Author: hareendrachamara
 *
 * Created on October 11, 2013, 10:53 PM
 */

#ifndef ISIS_AUTH_TEST_H
#define	ISIS_AUTH_TEST_H

#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define ARGDEFAULT 1345
#define MAXARRAYSIZE 50
#define SUCCESS 55;
int copy_area_address(struct area_addr* addr, u_char* name, int length);
int init_struct_list(int list1_size, int list2_size);
int test_equal_area_set_ret1();
int test_difsize_difareaset_ret0();
int test_equalsize_difadrsset_equaladdrlength_ret0();
int test_equalsize_difadrsset_difaddrlength_ret0();
int test_difsizeset_ret0();
int test_equalsize_equaladrsset_difaddrlength_ret1();




#endif	/* ISIS_AUTH_TEST_H */

