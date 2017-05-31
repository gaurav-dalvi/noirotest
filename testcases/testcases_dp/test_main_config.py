#!/usr/bin/python

import sys
import logging
import os
import datetime
import yaml
from time import sleep
from libs.gbp_heat_libs import gbpHeat
from libs.gbp_nova_libs import gbpNova
from libs.gbp_aci_libs import gbpApic
from libs.gbp_compute import Compute
from libs.keystone import Keystone
from libs.gbp_utils import *
from testcases.config import conf

APICSYSTEM_ID = conf['apic_system_id']
network_node = conf['network_node']
cntlr_ip = conf['controller_ip']
apic_ip = conf['apic_ip']
leaf1_ip = conf['leaf1_ip']
leaf2_ip = conf['leaf2_ip']
spine_ip = conf['spine_ip']
apic_passwd = conf['apic_passwd']
heat_temp_test = conf['main_setup_heat_temp']
num_hosts = conf['num_comp_nodes']
heat_stack_name = conf['heat_dp_stack_name']
pausetodebug = conf['pausetodebug']
test_parameters = conf['test_parameters']
plugin = conf['plugin-type']
gbpnova = gbpNova(cntlr_ip)
gbpheat = gbpHeat(cntlr_ip)
if plugin: #Incase of MergedPlugin
    if conf['apic_passwd']:
        gbpaci = gbpApic(apic_ip, mode='aim',
                         password=conf['apic_passwd'])
    else:
        gbpaci = gbpApic(apic_ip, mode='aim')
else:
    gbpaci = gbpApic(apic_ip,
		       apicsystemID=APICSYSTEM_ID) 
vmlist = ['VM1','VM2','VM3','VM4',
          'VM5','VM6','VM7','VM8',
	  'VM9','VM10','VM11','VM12'	
	 ]
        #Below L2Ps needed for APIC Verification
L2plist = [
           'demo_same_ptg_l2p_l3p_bd',
           'demo_diff_ptg_same_l2p_l3p_bd',
           'demo_diff_ptg_l2p_same_l3p_bd_1',
           'demo_diff_ptg_l2p_same_l3p_bd_2',
           'demo_srvr_bd', 'demo_clnt_bd'
          ]

class gbp_main_config(object):
    """
    The intent of this class is to setup the complete GBP config 
    needed for running all DP testcases
    """

    # Initialize logging
    #logging.basicConfig(level=logging.INFO)
    _log = logging.getLogger(__name__)
    _log.setLevel(logging.INFO)
    # create a logfile handler
    hdlr = logging.FileHandler('/tmp/test_gbp_dp_main_config.log')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    hdlr.setFormatter(formatter)
    # Add the handler to the logger
    _log.addHandler(hdlr)

    def __init__(self):
        """
        Iniatizing the test-cfg variables & classes
        """
	self.apicsystemID = conf['apic_system_id']
        self.nova_agg = conf['nova_agg_name']
        self.nova_az = conf['nova_az_name']
        self.comp_node = conf['az_comp_node']
        self.network_node = conf['network_node']
        self.cntlr_ip = conf['controller_ip']
        self.apic_ip = conf['apic_ip']
        self.leaf1_ip = conf['leaf1_ip']
        self.leaf2_ip = conf['leaf2_ip']
        self.spine_ip = conf['spine_ip']
        self.apic_passwd = conf['apic_passwd']
        self.heat_temp_test = conf['main_setup_heat_temp']
        self.num_hosts = conf['num_comp_nodes']
        self.heat_stack_name = conf['heat_dp_stack_name']
	self.pausetodebug = conf['pausetodebug']
        self.test_parameters = conf['test_parameters']
	self.plugin = conf['plugin-type']
        self.gbpnova = gbpNova(self.cntlr_ip)
        self.gbpheat = gbpHeat(self.cntlr_ip)
	if self.plugin: #Incase of MergedPlugin
            if conf['apic_passwd']:
                self.gbpaci = gbpApic(self.apic_ip, mode='aim',
                                      password=conf['apic_passwd'])
            else:
                self.gbpaci = gbpApic(self.apic_ip, mode='aim')
	else:
	    self.gbpaci = gbpApic(self.apic_ip,
			       apicsystemID=self.apicsystemID) 
	self.vmlist = ['VM1','VM2','VM3','VM4',
		       'VM5','VM6','VM7','VM8',
		       'VM9','VM10','VM11','VM12'	
		      ]
        #Below L2Ps needed for APIC Verification
        self.L2plist = [
                        'demo_same_ptg_l2p_l3p_bd',
                        'demo_diff_ptg_same_l2p_l3p_bd',
                        'demo_diff_ptg_l2p_same_l3p_bd_1',
                        'demo_diff_ptg_l2p_same_l3p_bd_2',
                        'demo_srvr_bd', 'demo_clnt_bd'
                       ]

    def _get_template_parameters(self):
        """Get parameters values for heat template.

        Get the list of parameters supported by the heat template,
        and search the testconfig.yaml file for any values that match.
        """
        parameter_args = []
        if self.heat_temp_test:
            fd = open(self.heat_temp_test, 'r')
            if not fd:
                return
            template_data = yaml.load(fd)
            for parameter in template_data['parameters']:
                if conf.get(parameter):
                    parameter_args.append(' -P ' + parameter + '=' + conf[parameter])
        if parameter_args:
            return ''.join(parameter_args)
        else:
             return None

    def setup(self):
        """
        Heat Stack Creates All Test Config
        """

        # Invoking Heat Stack for building up the Openstack Config
        # Expecting if at all there is residual heat-stack it
        # should be of the same name as that of this DP Reg
        self._log.info("\nCheck and Delete Residual Heat Stack")
        if self.gbpheat.cfg_all_cli(0, self.heat_stack_name) != 1:
           self._log.error(
               "\n ABORTING THE TESTSUITE RUN, Delete of Residual Heat-Stack Failed") 
           self.cleanup(stack=1) # Because residual stack-delete already failed above
           sys.exit(1)
        self._log.info("\n Checking for heat parameter args in config")
        parameter_args = self._get_template_parameters()
        self._log.info("\n Invoking Heat Stack for building config and VMs")
        if self.gbpheat.cfg_all_cli(1, self.heat_stack_name, heat_temp=self.heat_temp_test, parameter_args=parameter_args) == 0:
            self._log.error(
                "\n ABORTING THE TESTSUITE RUN, Heat-Stack create of %s Failed" % (self.heat_stack_name))
            self.cleanup()
            sys.exit(1)
        sleep(5)  # Sleep 5s assuming that all objects are created in APIC
        #Fetch the Tenant's DN for Openstack project 'admin'
        if self.plugin:
	    self.keyst = Keystone(self.cntlr_ip)
	    tnt = self.keyst.get_tenant_attribute('admin','id')
        else:
            tnt='admin'
        #Adding SSH-filter to Svc_Contract provided by Svc_Epgs
        self._log.info(
            "\n Adding SSH-Filter to Svc_epg created for every dhcp_agent")
        try:
	    if not self.plugin: #i.e. if 'classical plugin'
	        if not self.gbpaci.create_add_filter('admin'):
			raise Exception("Adding filter to SvcEpg failed")
	    else: #i.e. if MergedPlugin
	       if isinstance (run_remote_cli(
                              "python add_ssh_filter.py create",
                               self.cntlr_ip, 'root', 'noir0123'), tuple):
		        raise Exception("adding filter to SvcEpg failed in AIM")
	except Exception as e:
                 self._log.error(
                 "\nABORTING THE TESTSUITE RUN: " + repr(e))
	         self.cleanup() 
	         sys.exit(1)

    def verifySetup(self):
   	"""
	Verfies the Setup after being brought up
	"""
	self._log.info(
	    "\nVerify the Orchestrated Configuration in ACI")
	try:
	    self._log.info(
		"\n Verify the Operatonal State of EPGs")
	    operEpgs = self.gbpaci.getEpgOper('admin')
	    if operEpgs:
		vmstate = 'learned,vmm'
		for vm in self.vmlist:
		    notfound = 0
		    for epg,value in operEpgs.iteritems():
			#since each value is a dict itself,
                        #with key = vmname
			if vm in value.keys():
		           if not vmstate in value[vm]['status']:
			       raise Exception(
                                 'vm %s NOT Learned in Epg %s' %(vm,epg)
				 )
		        else:
			    notfound += 1
		    if notfound == len(operEpgs.keys()):    
			raise Exception(
			     'vm %s NOT found in APIC' %(vm))
            #Verify the BDs in OperState of Service EPGs
            #pop them out of the operEpgs
	    if not self.plugin: #Classical
                for bd in self.L2plist:
		    svcEpg = 'Shd-%s' %(bd)
		    if svcEpg in operEpgs.keys():
		        svcVal = operEpgs.pop(svcEpg)
		        if svcVal['bdname'] != bd \
			    or svcVal['bdstate'] != 'formed':
			        raise Exception(
			        'epg %s has Unresolved BD' %(svcEpg))
		    else:
		        raise Exception(
		        'SvcEpg %s NOT found in APIC' %(svcEpg))
	    else: #Merged-Plugin, verify sync-status of all BDs
		def aimcheck(obj,objtype):
		    tntname = self.gbpaci.getTenant(getName='admin')
		    if objtype == 'epg':
			cmd = "aimctl manager endpoint-group-get " +\
			 	"%s OpenStack %s | grep sync_status" \
				%(tntname, obj)
		    if objtype == 'bd':
		        cmd = "aimctl manager bridge-domain-get %s %s"\
			       %(tntname, obj) + " | grep sync_status" 
		    if not "synced" in run_remote_cli(cmd,
						      self.cntlr_ip,
						      'root',
						      'noir0123'
							):
			return 0
		    return 1
		for epg in operEpgs.keys():
		    if not aimcheck(epg,'epg'):
			raise Exception("AIM Univ: EPG %s NOT synced"
					%(epg))
	  	bdlist = [obj for obj in operEpgs.keys() if 'net_' in obj]
		apic_bd_state = self.gbpaci.getBdOper('admin')
	 	for bd in bdlist:
		    if not aimcheck(bd,'bd'):
			raise Exception("AIM Univ: BD %s NOT synced"
					%(bd))
		    if apic_bd_state[bd]['vrfstate'] != 'formed':
			raise Exception("APIC Univ: Vrf of BD %s NOT resolved"
					%(bd))
		
	except Exception as e:
	    self._log.error(
            '\nSetup Verification Failed Because of this Issue: '+repr(e))
            self._log.error(
            "\nABORTING THE TESTSUITE RUN, on Setup Verification Failure")
	    if self.pausetodebug:
	       PauseToDebug()
  	    return 0
	return 1

    def reloadAci(self,nodetype='borderleaf'):
        """
        Reload the leaf or Spine
        """
        if nodetype == 'borderleaf':
           self.gbpaci.reboot_aci(self.leaf1_ip)
        if nodetype == 'leaf':
           self.gbpaci.reboot_aci(self.leaf2_ip)
        if nodetype == 'spine':
           self.gbpaci.reboot_aci(self.spine_ip)
           
    def restartAgent(self,compNodeIP):
        """
        Restart Agent OVS
        """
        state = action_service(compNodeIP)
        if state:
           sleep(5)
           return 1
        else:
           return 0
        
    def cleanup(self,stack=0,avail=0):
        # Need to call for instance delete if there is an instance
        self._log.info("Cleaning Up The Test Config")
        if stack == 0:
           self.gbpheat.cfg_all_cli(0, self.heat_stack_name)
	   if self.plugin:
	       # Remove the noiro-ssh filter from AIM
	       run_remote_cli("python add_ssh_filter.py delete",
                            self.cntlr_ip, 'root', 'noir0123')
           # Ntk namespace cleanup in Network-Node.. VM names are static
           # throughout the test-cycle
           del_netns(self.network_node)
