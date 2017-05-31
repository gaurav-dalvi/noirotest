#!/usr/bin/python

import datetime
import logging
import sys

from time import sleep
from testcases.config import conf
from libs.gbp_aci_libs import gbpApic
from libs.gbp_crud_libs import GBPCrud
from libs.gbp_nova_libs import gbpNova
from libs.raise_exceptions import *
from libs.gbp_utils import *
from traff_from_extgw import *
from traff_from_allvms_to_extgw import NatTraffic

# Initialize logging
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.ERROR)
# create a logfile handler
hdlr = logging.FileHandler('/tmp/test_nat_functionality.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
hdlr.setFormatter(formatter)
# Add the handler to the logger
LOG.addHandler(hdlr)

# CONSTANTS & CONFIG DEFINITION
PLUGIN_TYPE = conf['plugin-type']
CNTRLRIP = conf['controller_ip']
APICIP = conf['apic_ip']
NTKNODE = conf['network_node']
EXTRTR = conf['ext_rtr']
EXTRTR_IP1 = conf['extrtr_ip1']
EXTRTR_IP2 = conf['extrtr_ip2']
GWIP1_EXTRTR = conf['gwip1_extrtr']
GWIP2_EXTRTR = conf['gwip2_extrtr']
NOVA_AGG = conf['nova_agg_name']
AVAIL_ZONE = conf['nova_az_name']
AZ_COMP_NODE = conf['az_comp_node']
PAUSETODEBG = conf['pausetodebug']
EXTSEG_PRI = conf['primary_L3out']
EXTSEG_SEC = conf['secondary_L3out']
NATPOOLNAME1 = 'GbpNatPoolTest1'
NATPOOLNAME2 = 'GbpNatPoolTest2'
NATIPPOOL1 = '50.50.50.0/24'
NATIPPOOL2 = '60.60.60.0/24'
SNATPOOL = '55.55.55.0/24'
SNATCIDR = '55.55.55.1/24'
L3PNAME = 'L3PNat'
L3PIPPOOL = '20.20.20.0/24'
L3PPREFLEN = 26
L2PNAME = 'L2PNat'
PTG1NAME = 'TestPtg1'
PTG2NAME = 'TestPtg2'
EXTPOL_MGMT = 'MgmtExtPol'
EXTPOL_DC = 'DcExtPol'
VM1_NAME = 'TestVM1'
VM2_NAME = 'TestVM2'
VMLIST = [VM1_NAME, VM2_NAME]
traffic = NatTraffic(
            CNTRLRIP, VMLIST, NTKNODE)
ACTION = 'ActAllow'
CLSF_ICMP = 'ClsIcmp'
CLSF_TCP = 'ClsTcp'
PR_ICMP = 'PrIcmp'
PR_TCP = 'PrTcp'
PRS_ICMP_TCP = 'PrsIcmpTcp'
PRS_ICMP = 'PrsIcmp'
PRS_TCP = 'PrsTcp'
gbpcrud = GBPCrud(CNTRLRIP)
gbpnova = gbpNova(CNTRLRIP)
if PLUGIN_TYPE:
    from libs.neutron import *
    neutron = neutronCli(CNTRLRIP)

class NatFuncTestMethods(object):
    """
    This is a GBP NAT Functionality TestCase
    """
    # NOTE: In this code structure, we have mostly re-used the same
    # local variable, as on every instance/invoke of the method new
    # value will be associated to the local variable within the
    # function scope

    def create_external_networks(self):
            LOG.info(
            "\n## Create External Networks for L3Outs:: %s & %s ##" %(EXTSEG_PRI, EXTSEG_SEC))
            try:
                aimntkcfg_primary = '--apic:distinguished_names type=dict'+\
                 ' ExternalNetwork='+\
                 'uni/tn-common/out-%s/instP-MgmtExtPol' %(EXTSEG_PRI)
                aimsnat = '--apic:snat_host_pool True'
                neutron.netcrud(EXTSEG_PRI,'create',external=True,
                            shared=True, aim = aimntkcfg_primary)
                self.EXTSUB1 = neutron.subnetcrud('extsub1','create',EXTSEG_PRI,
                               cidr=NATIPPOOL1,extsub=True)
                self.EXTSUB2 = neutron.subnetcrud('extsub3','create',EXTSEG_PRI,
                               cidr=SNATPOOL,extsub=True,aim=aimsnat)


                aimntkcfg_sec = '--apic:distinguished_names type=dict'+\
                 ' ExternalNetwork='+\
                 'uni/tn-common/out-%s/instP-DcExtPol' %(EXTSEG_SEC)
                aimsnat = '--apic:snat_host_pool True'
                neutron.netcrud(EXTSEG_SEC,'create',external=True,
                            shared=True, aim = aimntkcfg_sec)
                self.EXTSUB4 = neutron.subnetcrud('extsub4','create',EXTSEG_SEC,
                               cidr=SNATPOOL,extsub=True,aim=aimsnat)
	    except Exception as e:
		LOG.ERROR("External Network Create Failed for MergedPlugin")
		for l3out in [EXTSEG_PRI, EXTSEG_SEC]:
	            neutron.runcmd('neutron net-delete %s' %(l3out))
	    	return 0
	    return 1
	    

    def addhostpoolcidr(self,fileloc='/etc/neutron/neutron.conf',
                        l3out=EXTSEG_PRI,delete=False,
                        restart=True,flag=''):
        """
        Add host_pool_cidr config flag and restarts neutron-server
        fileloc :: location of the neutron config
                   file in which apic_external_network
                   section is defined
        """
        patternchk = 'host_pool_cidr'
        pattern = 'host_pool_cidr=%s' %(SNATCIDR)
        section = 'apic_external_network:%s' %(l3out)
        if not delete:
            if flag == 'default_external_segment_name':
               LOG.info(
               "\nAdding default_external_segment_name to neutron conf")
               pat='default_external_segment_name=%s' %(l3out)
               sect='group_policy_implicit_policy'
               editneutronconf(CNTRLRIP,
                            fileloc,
                            pat,
                            section=sect
                           )
            else:
                LOG.info("\nAdding host_pool_cidr to neutron conf")
                editneutronconf(CNTRLRIP,
                            fileloc,
                            pattern,
                            section=section
                           )
        if delete:
            LOG.info(
            "\nDeleting if any, host_pool_cidr & def_ext_seg_name"
            "from neutron conf")
            if not flag:
                editneutronconf(CNTRLRIP,
                            fileloc,
                            'default_external_segment_name',
                            add=False,
                            restart=False
                           )
            editneutronconf(CNTRLRIP,
                            fileloc,
                            patternchk,
                            add=False) 

    def testCreateExtSegWithDefault(self,extsegname):
        """
        Create External Segment
        """
        LOG.info(
        "\nStep: Create External Segment %s\n" %(extsegname))
        if PLUGIN_TYPE:
	    if extsegname == EXTSEG_PRI:
		extsub = self.EXTSUB1
	    else:
		extsub = self.EXTSUB4
            self.extsegid = gbpcrud.create_gbp_external_segment(
                                        extsegname,
                                        subnet_id = extsub,
                                        external_routes = [{
                                           'destination':'0.0.0.0/0',
                                           'nexthop': None}],
                                        shared=True
                                       )
	else:
            self.extsegid = gbpcrud.create_gbp_external_segment(
                                       extsegname,
                                       external_routes = [{
                                           'destination':'0.0.0.0/0',
                                           'nexthop': None}],
					shared=True
                                       )
        if self.extsegid == 0:
            LOG.error(
            "\n///// Step: External Segment Creation %s failed /////"
            %(extsegname))
            return 0
        else:
            return self.extsegid

    def testCreateNatPoolAssociateExtSeg(self,poolname='',natpool='',extsegid=''):
        """
        Create a NAT pool and associate the existing External Segment
        """
        LOG.info(
        "\nStep: Create a NAT pool and associate the existing External Segment\n")
        if natpool == '':
           natpool = NATIPPOOL1
        if poolname == '':
           poolname = NATPOOLNAME1
        if extsegid == '':
           extsegid = self.extsegid
        self.nat_pool_id = gbpcrud.create_gbp_nat_pool(
                                        poolname,
                                        ip_pool = natpool,
                                        external_segment_id = extsegid)
        if self.nat_pool_id == 0:
            LOG.error(
                "\n///// Create the NAT pool with reference to"
                  " the existing External Segment failed /////")
            return 0
	return 1

    def testUpdateNatPoolAssociateExtSeg(self,extsegid):
        """
        Update External Segment in a NAT Pool
        """
        # Since self.nat_pool_id is the ONLY natpool in the system hence making it
        # the default value
        LOG.info(
            "\nStep: Update a NAT pool and associate the existing External Segment\n")
        if gbpcrud.update_gbp_nat_pool(
                                        self.nat_pool_id,
                                        external_segment_id = extsegid
                                        ) == 0:
           LOG.error(
                "\n///// Update External Segment in" 
                " existing NAT pool failed /////")
           return 0
	return 1

    def testCreatePtgDefaultL3p(self):
        """
        Step to Create Policy Target group with Default L3
        Fetch the UUID of the 'default' L3Policy
        """
        LOG.info(
                  "\nStep: Create Policy Target group with Default L3\n")
        self.ptg1id = gbpcrud.create_gbp_policy_target_group(
                                     PTG1NAME)
        if self.ptg1id == 0:
            LOG.error(
            "\n///// Create Policy Target group with Default L3 failed /////")
                
            return 0
        self.defaultl3pid = gbpcrud.verify_gbp_l3policy('default') 
        if self.defaultl3pid == 0:
           LOG.error("\n///// Failed to fetch UUID of Default L3P /////")
           return 0
	return 1

    def testCreateNonDefaultL3pAndL2p(self):
        """
        Step to Create Non-default L3P
        """
        LOG.info("\nStep: Create non-default L3Policy and L2Policy\n")
        self.nondefaultl3pid = gbpcrud.create_gbp_l3policy(
                                               L3PNAME,
                                               ip_pool=L3PIPPOOL,
                                               subnet_prefix_length=L3PPREFLEN)
        if self.nondefaultl3pid == 0:
            LOG.error(
            "\n///// Creation of non-default L3Policy failed /////")
            
            return 0
        self.l2policy_id = gbpcrud.create_gbp_l2policy(
                                L2PNAME,
                                l3_policy_id=self.nondefaultl3pid)
        if self.l2policy_id == 0:
            LOG.error(
            "\n///// Creation of non-default L2Policy failed /////")
            return 0
	return 1

    def testCreatePtgWithNonDefaultL3p(self):
        """
        Step to Create Policy Target group with Created L3
        """
        LOG.info("\nStep: Create Policy Target group with Created L3\n")
        self.ptg2id = gbpcrud.create_gbp_policy_target_group(
                                     PTG2NAME,
                                     l2_policy_id=self.l2policy_id)
        if self.ptg2id == 0:
            LOG.error(
            "\n////// Create Policy Target group "
            "with non-default L3Policy failed /////")
            return 0
	return 1

    def testAssociateExtSegToBothL3ps(self,extsegid='',both=True,l3ptype=''):
        """
        Step to Associate External Segment to 
        both default & non-default L3Ps
        both: True/False, defaulted to use both L3Ps
              else(False) user should pass the l3ptype
        l3ptype: valid strings are 'default' or 'nondefault'
        """
        if extsegid == '':
           extsegid = self.extsegid
        if both:
            LOG.info(
                     "\nStep: Associate External Segment to both L3Ps\n")
            for l3p in [self.defaultl3pid,self.nondefaultl3pid]:
                if gbpcrud.update_gbp_l3policy(l3p,
                                                property_type='uuid',
                                                external_segments=extsegid
                                                ) == 0:
                    LOG.error(
                    "\n///// Associate External Segment to L3P failed /////")
                    return 0
        else:
            if l3ptype == 'default':
                l3p = self.defaultl3pid
            else:
                l3p = self.nondefaultl3pid
            LOG.info("\nStep:Associate External Segment to Single L3P")
            if gbpcrud.update_gbp_l3policy(l3p,
                                                property_type='uuid',
                                                external_segments=extsegid
                                                ) == 0:
               LOG.error(
               "\n///// Associate External Segment to Single L3P failed /////")
               return 0 
	return 1
        
    def testCreatePolicyTargetForEachPtg(self):
        """
        Created Port Targets
        """
        LOG.info(
                 "\nStep: Create Policy Targets for each of the two PTGs \n")
        self.pt1id = gbpcrud.create_gbp_policy_target('pt1', PTG1NAME, 1)
        if self.pt1id == 0:
            LOG.error(
            "\n///// Creation of Policy Targe failed for PTG=%s /////"
            %(PTG1NAME))
            
            return 0
        self.pt2id = gbpcrud.create_gbp_policy_target('pt2', PTG2NAME, 1)
        if self.pt2id == 0:
            LOG.error(
            "\n///// Creation of Policy Targe failed for PTG=%s /////"
            %(PTG2NAME))
            return 0
	return 1

    def testCreateUpdateExternalPolicy(self,update=0,delete=0,
                                       extseg='',extpol='default'):
        """
        Create ExtPolicy with ExtSegment
        Apply Policy RuleSets
        update:: 1, then MUST pass extseg(the new extsegid to which
                    this existing ExtPol should now associate to
        """
        if extpol == 'default':
           self.extpolname = EXTPOL_MGMT
        else:
           self.extpolname = EXTPOL_DC
        if delete == 1:
            LOG.info("\nStep: Delete ExtPolicy")  
            if gbpcrud.delete_gbp_external_policy(
                           self.extpolid
                           ) == 0:
               LOG.error(
                    "\n///// Deletion of External Policy failed /////")   
               return 0
        elif update == 1:
            LOG.info(
            "\nStep: Update ExtPolicy with External Segment")  
            if gbpcrud.update_gbp_external_policy(
                           self.extpolname,
                           external_segments=[extseg]
                           ) == 0:
               LOG.error(
               "\n///// Updation of External Policy with ExtSeg failed /////")   
               return 0
        else:
           LOG.info(
           "\nStep: Create ExtPolicy with ExtSegment and Apply PolicyRuleSets\n")
           if extseg == '':
              extseg = self.extsegid    
           self.extpolid = gbpcrud.create_gbp_external_policy(
                             self.extpolname,
                             external_segments=[extseg]
                                                              )
           if self.extpolid == 0:
              LOG.error(
              "\n ///// Creation of External Policy failed /////")
              return 0
           return self.extpolid
	return 1
   
    def testVerifyCfgdObjects(self,nat_type='dnat'):
        """
        Verify all the configured objects and their atts
        """
        LOG.info(
                 "\nStep: Verify the Configured Objects and their Attributes\n")
        if gbpcrud.verify_gbp_any_object('l3_policy',
                                               self.nondefaultl3pid,
                                               external_segments = self.extsegid,
                                               l2_policies = self.l2policy_id,
                                               ip_pool = L3PIPPOOL
                                              ) == 0:  
           LOG.error("\n///// Verify for L3Policy Failed /////")
           return 0
        if gbpcrud.verify_gbp_any_object('l2_policy',
                                               self.l2policy_id,
                                               l3_policy_id = self.nondefaultl3pid,
                                               policy_target_groups = self.ptg2id
                                              ) == 0:
           LOG.error("\n///// Verify for L2Policy Failed /////")
           return 0
        if nat_type == 'dnat':
            if gbpcrud.verify_gbp_any_object('external_segment',
                                               self.extsegid,
                                               l3_policies = [self.defaultl3pid,
                                                              self.nondefaultl3pid],
                                               nat_pools = self.nat_pool_id,
                                               external_policies = self.extpolid
                                              ) == 0:
                LOG.error("\n///// Verify for DNAT ExtSeg Failed /////")
                return 0
        else:
            if gbpcrud.verify_gbp_any_object('external_segment',
                                               self.extsegid,
                                               l3_policies = [self.defaultl3pid,
                                                              self.nondefaultl3pid],
                                               external_policies = self.extpolid
                                              ) == 0:
               
                LOG.error("\n///// Verify for SNAT ExtSeg Failed /////")
                return 0
	return 1

    def testLaunchVmsForEachPt(self,az2='',same=False):
        """
        Launch VMs in two diff avail-zones
        az2:: second avail-zone, az1=nova(default)
        same:: True, then VMs launched in same avail-zone
        """
        az1 = 'nova' #default in openstack
        if same:
           az2 = az1
           LOG.info("\nStep: Launch VMs in same avail-zones\n")
        else:
            LOG.info("\nStep: Launch VMs in two diff avail-zones\n")
        # launch Nova VMs
        if gbpnova.vm_create_api(VM1_NAME,
                                      conf['vm_image'],
                                      self.pt1id[1],
                                      flavor_name=conf['vm_flavor'],
                                      avail_zone=az1) == 0:
           LOG.error(
           "\n///// VM Create using PTG %s failed /////" %(PTG1NAME))
           return 0
        if gbpnova.vm_create_api(VM2_NAME,
                                      conf['vm_image'],
                                      self.pt2id[1],
                                      flavor_name=conf['vm_flavor'],
                                      avail_zone=az2) == 0:
           LOG.error(
           "\n///// VM Create using PTG %s failed /////" %(PTG2NAME))
           return 0
	return 1

    def testAssociateFipToVMs(self,ExtSegName=EXTSEG_PRI,ic=False):
        """
        Associate FIPs to VMs
        ic:: True, means FIP already exists, user needs
                to statically interchange the FIP among the VMs
        """
        VMs = [VM1_NAME,VM2_NAME]
        if not ic:
            LOG.info("\nStep: Dynamically Associate FIPs to VMs\n")
            self.vm_to_fip = {}
            for vm in VMs:
                results = gbpnova.action_fip_to_vm(
                                          'associate',
                                          vm,
                                          extsegname=ExtSegName
                                          )
                if not results:
                   LOG.error(
                   "\n///// Dynamic Association FIP to VM %s failed /////" %(vm))
                   #if the above function is called for a negative check
                   #then it may or may not have already created the FIPs
                   #So ensure to delete those FIPs(apparently this we were
                   #not doing so TC-4 was failing at Step=Negative Check
                   gbpnova.delete_release_fips()
                   return 0
                else:
                   self.vm_to_fip[vm] = results[0]
        if ic:
            LOG.info(
            "\nStep: Statically Inter-Changing Association of FIPs to VMs\n")
            if gbpnova.action_fip_to_vm(
                                            'associate',
                                            VMs[0],
                                            vmfip=self.vm_to_fip[VMs[1]]
                                            ) and \
               gbpnova.action_fip_to_vm(
                                            'associate',
                                            VMs[1],
                                            vmfip=self.vm_to_fip[VMs[0]]
                                            ):
               print "Success in Static Assignment of FIP to VMs"
            else:
               LOG.error(
               "\n///// Static Association of FIP to VM %s failed /////")
               return 0
	return 1

    def testDisassociateFipFromVMs(self,release_fip=True,vmname=False):
        """
        Disassociate FIPs from VMs
        vmname:: Pass specific VM name string to disassociate FIP
        """
        if vmname:
            vmname = VM2_NAME
            LOG.info("\nStep: Disassociate FIP from VM %s\n" %(vmname))
            if not gbpnova.action_fip_to_vm(
                                          'disassociate',
                                          vmname,
                                          vmfip = self.vm_to_fip[vmname]
                                          ):
               LOG.error(
               "\n///// Disassociating FIP from VM %s failed /////" %(vm))
               return 0
        else:
            LOG.info("\nStep: Disassociate FIPs from all VMs\n")
            for vm,fip in self.vm_to_fip.iteritems():
                if not gbpnova.action_fip_to_vm(
                                          'disassociate',
                                          vm,
                                          vmfip = fip
                                          ):
                    LOG.error(
                    "\n//// Disassociating FIP from VM %s failed ////" %(vm))
                    return 0
        if release_fip:
           gbpnova.delete_release_fips()
	return 1

    def testApplyUpdatePrsToPtg(self,ptgtype,prs):
        """
        Update Internal PTG & External Pol
        Provide the PolicyRuleSet
        ptgtype:: 'internal' or 'external'
        """
        if ptgtype == 'external':
            LOG.info(
                "\nStep: Updating External Policy by applying Policy RuleSets\n")
            if gbpcrud.update_gbp_external_policy(
                                                 self.extpolname,
                                                 consumed_policy_rulesets=[prs]
                                                 ) == 0:
               LOG.error(
               "\n///// Updating External Policy %s failed /////"
               %(self.extpolid))
               return 0
        if ptgtype == 'internal':
           LOG.info(
                "\nStep: Updating Policy Target Group by applying Policy RuleSets\n")
           for ptg in [PTG1NAME, PTG2NAME]:
               if gbpcrud.update_gbp_policy_target_group(
                                        ptg,
                                        provided_policy_rulesets=[prs]
                                        ) == 0:
                  LOG.error(
                  "\n///// Updating PTG %s failed /////" %(ptg))
                  return 0
	return 1

    def testCreateNsp(self):
        """
        Create a Network Service Profile
        """
        LOG.info(
                "\nStep: Creating a Network Service Policy")
        self.nspuuid = gbpcrud.create_gbp_network_service_policy_for_nat('TestNsp')
        if self.nspuuid == 0:
           return 0
	return 1

    def testApplyRemoveNSpFromPtg(self,nspuuid=''):
        """
        Update to Apply or Remove NSP from Internal PTGs
        """
        if nspuuid == None:
           LOG.info(
             "\nStep: Removing Network Service Policy from Internal PTGs")
           nspuuid = None
        else:
           LOG.info(
             "\nStep: Applying Network Service Policy from Internal PTGs")
           nspuuid = self.nspuuid
        for ptg in [PTG1NAME, PTG2NAME]:
               if gbpcrud.update_gbp_policy_target_group(
                                   ptg,
                                   network_service_policy=nspuuid,
                                   ) == 0:
                  LOG.error(
                  "\n///// Updating PTG with NSP %s failed /////" %(ptg))
                  return 0
	return 1

    def testDeleteNatPool(self):
        """
        Deletes all available NAT Pool in the system
        """
        natpool_list = gbpcrud.get_gbp_nat_pool_list()
        if len(natpool_list) :
              for natpool in natpool_list:
                 gbpcrud.delete_gbp_nat_pool(natpool)
	return 1

    def testTrafficFromExtRtrToVmFip(self,extgwrtr,fip=False):
        """
        Ping and TCP test from external router to VMs
        """
        LOG.info("\nStep: Ping and TCP test from external router\n")
        if fip:
           vmfips = self.vm_to_fip[VM1_NAME]
        else:
           vmfips = gbpnova.get_floating_ips(ret=1)
	if not vmfips:
		LOG.error(
		"\n///// There are no FIPs to test Traffic /////")
		return 0
        run_traffic = traff_from_extgwrtr(
                                          extgwrtr,
                                          vmfips
                                          )
        if isinstance(run_traffic, dict):
            LOG.error(
            "\n///// Following Traffic Test from External"
            " GW Router Failed == %s /////" % (run_traffic))
            return 0
	return 1
        
    def testTrafficFromVMsToExtRtr(self,extgwips,vmname=True):
        """
        Ping and TCP traffic from VMs to ExtRtr
        """
        if vmname:
            vmlist = [VM2_NAME]
        else:
            vmlist = VMLIST
        LOG.info("\nStep: Ping and TCP traffic from VMs to ExtRtr\n")
        retry = 1
        while retry:
            failed = {}
            for srcvm in vmlist:
                run_traffic = traffic.test_traff_anyvm_to_extgw(
                                                      srcvm, extgwips)
                if run_traffic == 2:
                   LOG.error(
                   "\n///// Traffic VM %s Unreachable, Test = Aborted /////"
                   %(srcvm))
                   return 0
                if isinstance(run_traffic, tuple):
                    failed[srcvm] = run_traffic[1]
            if len(failed) and retry == 3:
                LOG.info(
                "\nFollowing Traffic Test Failed After Applying "
                "ICMP-TCP-Combo Contract == %s" % (failed))
                return 0
            elif len(failed) and retry < 3:
               LOG.info("Sleep for 10 sec before retrying traffic")
               sleep(10)
               retry += 1
            else:
               break
	return 1

    def AddSShContract(self,apicip):
        """
        Adds SSH contract between NS and EPG
        Needed for SNAT Tests
        """
       	LOG.info(
                "\n ADDING SSH-Filter to Svc_epg created for every dhcp_agent")
	if not PLUGIN_TYPE:
                if conf.get('apic_passwd'):
                    aci=gbpApic(apicip, password=conf['apic_passwd'])
                else:
                    aci=gbpApic(apicip)
        	svcepglist = [
                	'TestPtg1',
                	'L2PNat'
                	]
        	aci.create_add_filter(svcepglist)
	else:
		if isinstance (run_remote_cli(
                              "python add_ssh_filter.py create",
                               CNTRLRIP, 'root', 'noir0123'), tuple):
                        LOG.warning("adding filter to SvcEpg failed in AIM")
			return 0
        sleep(15) # TODO: SSH/Ping fails possible its taking time PolicyDownload
	return 1

    def DeleteOrCleanup(self,action,obj=None,uuid=''):
        """
        Specific Delete or Blind Cleanup
        obj & uuid need to be passed ONLY when action='delete'
        """
        if action == 'delete':
           if obj == 'external_segment' and uuid != '':
              gbpcrud.delete_gbp_external_segment(uuid)
           elif obj == 'nat_pool' and uuid != '':
              gbpcrud.delete_gbp_nat_pool(uuid)
           elif obj == 'external_policy' and uuid != '':
              gbpcrud.delete_gbp_external_policy(uuid)
           elif obj == 'policy_target_group' and uuid != '':
              gbpcrud.delete_gbp_policy_target_group(uuid)
           else:
              LOG.info("\n Incorrect params passed for delete action")
        if action == 'cleanup':
           LOG.info("\nStep: Blind CleanUp of Resources initiated")
           LOG.info("\nStep: Blind CleanUp: VMs Delete")
           for vm in [VM1_NAME, VM2_NAME]:
               gbpnova.vm_delete(vm)
           LOG.info("\nStep: Blind CleanUp: Release FIPs")
           gbpnova.delete_release_fips()
           LOG.info("\nStep: Blind CleanUp: Delete PTs")
           pt_list = gbpcrud.get_gbp_policy_target_list()
           if len(pt_list):
              for pt in pt_list:
                gbpcrud.delete_gbp_policy_target(pt, property_type='uuid')
           LOG.info("\nStep: Blind CleanUp: Delete PTGs")
           ptg_list = gbpcrud.get_gbp_policy_target_group_list()
           if len(ptg_list):
              for ptg in ptg_list:
                gbpcrud.delete_gbp_policy_target_group(ptg, property_type='uuid')
           LOG.info("\nStep: Blind CleanUp: Delete L2Ps")
           l2p_list = gbpcrud.get_gbp_l2policy_list()
           if len(l2p_list):
              for l2p in l2p_list:
                 gbpcrud.delete_gbp_l2policy(l2p, property_type='uuid')
           LOG.info("\nStep: Blind CleanUp: Delete L3Ps")
           l3p_list = gbpcrud.get_gbp_l3policy_list()
           if len(l3p_list) :
              for l3p in l3p_list:
                 gbpcrud.delete_gbp_l3policy(l3p, property_type='uuid')
           LOG.info("\nStep: Blind CleanUp: Delete NSPs")
           gbpcrud.delete_gbp_network_service_policy()
           LOG.info("\nStep: Blind CleanUp: Delete NAT Pools")
           natpool_list = gbpcrud.get_gbp_nat_pool_list()
           if len(natpool_list) :
              for natpool in natpool_list:
                 gbpcrud.delete_gbp_nat_pool(natpool)
           LOG.info("\nStep: Blind CleanUp: Delete External Pols")
           extpol_list = gbpcrud.get_gbp_external_policy_list()
           if len(extpol_list) :
              for extpol in extpol_list:
                 gbpcrud.delete_gbp_external_policy(extpol)
           LOG.info("\nStep: Blind CleanUp: Delete Ext Segs")
           extseg_list = gbpcrud.get_gbp_external_segment_list()
           if len(extseg_list) :
              for extseg in extseg_list:
                 gbpcrud.delete_gbp_external_segment(extseg)
           LOG.info("\nStep: Blind CleanUp of Resources: Completed")
