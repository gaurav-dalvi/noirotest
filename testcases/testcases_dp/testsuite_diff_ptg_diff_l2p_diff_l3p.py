#!/usr/bin/python

import sys
import logging
import os
import datetime
import string
from libs.gbp_conf_libs import Gbp_Config
from libs.gbp_verify_libs import Gbp_Verify
from libs.gbp_fab_traff_libs import Gbp_def_traff
from libs.gbp_pexp_traff_libs import Gbp_pexp_traff
from libs.raise_exceptions import *
from testsuites_setup_cleanup import super_hdr

class test_diff_ptg_diff_l2p_diff_l3p(object):
    """
    This is a TestCase Class comprising
    all Datapath testcases for the Test Header:   
    diff_ptg_diff_l2p_diff_l3p
    Every new testcases should be added as a new method in this class
    and call the testcase method inside the 'test_runner' method
    """
    # Initialize logging
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s - %(message)s', level=logging.WARNING)
    _log = logging.getLogger( __name__ )
    hdlr = logging.FileHandler('/tmp/testsuite_diff_ptg_diff_l2p_diff_l3p.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)
    _log.setLevel(logging.DEBUG)

    def __init__(self):

      self.gbpcfg = Gbp_Config()
      self.gbpverify = Gbp_Verify()
      self.gbpdeftraff = Gbp_def_traff()
      stack_name = super_hdr.stack_name
      heat_temp = super_hdr.heat_temp
      self.objs_uuid = self.gbpverify.get_uuid_from_stack(super_hdr.heat_temp,stack_name)
      self.ptg_1 = self.objs_uuid['demo_diff_ptg_l2p_l3p_ptg1_id']
      self.ptg_2 = self.objs_uuid['demo_diff_ptg_l2p_l3p_ptg2_id']
      #self.test_2_prs = self.objs_uuid['demo_ruleset_norule_id'] #TODO: Need to enable this and remove the below line once test is done
      self.test_2_prs = 'demo_ruleset_norule'
      self.test_3_prs = self.objs_uuid['demo_ruleset_icmp_id']
      self.test_4_prs = self.objs_uuid['demo_ruleset_tcp_id']
      self.test_5_prs = self.objs_uuid['demo_ruleset_udp_id']
      self.test_6_prs = self.objs_uuid['demo_ruleset_icmp_tcp_id']
      self.test_7_prs = self.objs_uuid['demo_ruleset_icmp_udp_id']
      self.test_8_prs = self.objs_uuid['demo_ruleset_tcp_udp_id']
      self.test_9_prs = self.objs_uuid['demo_ruleset_all_id']


    def test_runner(self,log_string,location):
        """
        Method to run all testcases
        """
        self.vm_loc = location
        test_list = [self.test_1_traff_with_no_prs,
                    self.test_2_traff_app_prs_no_rule,
                    self.test_3_traff_apply_prs_icmp,
                    self.test_4_traff_apply_prs_tcp,
                    self.test_5_traff_apply_prs_udp,
                    self.test_6_traff_apply_prs_icmp_tcp,
                    self.test_7_traff_apply_prs_icmp_udp,
                    self.test_8_traff_apply_prs_tcp_udp,
                    self.test_9_traff_apply_prs_all_proto,
                    self.test_10_traff_rem_prs
                    ]
                 
        for test in test_list:
            try:
               if test()!=1:
                  raise TestFailed("%s_%s_%s == FAILED" %(self.__class__.__name__.upper(),log_string.upper(),string.upper(test.__name__.lstrip('self.'))))
               else:
                  if 'test_1' in test.__name__ or 'test_2' in test.__name__:
                     self._log.info("%s_%s_%s 10 subtestcases == PASSED" %(self.__class__.__name__.upper(),log_string.upper(),string.upper(test.__name__.lstrip('self.'))))
                  else:
                     self._log.info("%s_%s_%s == PASSED" %(self.__class__.__name__.upper(),log_string.upper(),string.upper(test.__name__.lstrip('self.'))))
            except TestFailed as err:
               print err


    def verify_traff(self):
        """
        Verifies thes expected traffic result per testcase
        """
        #return 1 #Jishnu
        #Incase of Diff PTG Diff L2P and DIff L3P all traffic is disallowed irrespective what Policy-Ruleset is applied
        # Hence verify_traff will check for all protocols including the implicit ones
        gbpcfg = Gbp_Config()
        vm10_ip = gbpcfg.get_vm_subnet('VM10')[0]
        vm10_subn = gbpcfg.get_vm_subnet('VM10')[1]
        dhcp_ns = gbpcfg.get_netns('172.28.184.63',vm10_subn)
        if self.vm_loc == 'diff_host_same_leaf': #Jishnu: TODO: Change the hardcoded com-node/ntk-node IP after test
           vm12_ip = gbpcfg.get_vm_subnet('VM12',ret='ip')
           print vm10_ip, vm10_subn, vm12_ip, dhcp_ns
           gbppexptraff = Gbp_pexp_traff('172.28.184.63',dhcp_ns,vm10_ip,vm12_ip)
        if self.vm_loc == 'same_host':
           vm11_ip = gbpcfg.get_vm_subnet('VM11',ret='ip')
           print vm10_ip, vm10_subn, vm11_ip, dhcp_ns
           gbppexptraff = Gbp_pexp_traff('172.28.184.63',dhcp_ns,vm10_ip,vm11_ip)
        results=gbppexptraff.test_run()
        print 'Results from the Testcase == ', results
        failed={}
        failed = {key: val for key,val in results.iteritems() if val == 1}
        if len(failed) > 0:
            print 'Following traffic_types %s = Failed' %(failed)
            return 0
        else:
            return 1

    def test_1_traff_with_no_prs(self):
        """
        Run traff test when PTG is with NO Contract
        """
        return self.verify_traff()

    def test_2_traff_app_prs_no_rule(self):
        """
        Update the in-use PTG with a PRS which has NO-Rule
        Send traff
        """
        prs = self.test_2_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           print 'Updating PTG = Failed'
           return 0

    def test_3_traff_apply_prs_icmp(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_3_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           print 'Updating PTG == Failed'
           return 0

    def test_4_traff_apply_prs_tcp(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_4_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           print 'Updating PTG = Failed'
           return 0

    def test_5_traff_apply_prs_udp(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_5_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           return 0

    def test_6_traff_apply_prs_icmp_tcp(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_6_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           return 0

    def test_7_traff_apply_prs_icmp_udp(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_7_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           return 0

    def test_8_traff_apply_prs_tcp_udp(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_8_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           return 0

    def test_9_traff_apply_prs_all_proto(self):
        """
        Apply Policy-RuleSet to the in-use PTG
        Send traffic
        """
        prs = self.test_9_prs
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="%s=scope" %(prs))\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="%s=scope" %(prs)) !=0:
           return self.verify_traff()
        else:
           return 0

    def test_10_traff_rem_prs(self):
        """
        Remove the PRS/Contract from the PTG
        Test all traffic types
        """
        if self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_1,provided_policy_rule_sets="")\
           and self.gbpcfg.gbp_policy_cfg_all(2,'group',self.ptg_2,consumed_policy_rule_sets="") !=0:
           return self.verify_traff()
        else:
           return 0

