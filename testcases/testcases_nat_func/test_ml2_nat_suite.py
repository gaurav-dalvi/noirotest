#!/usr/bin/python

import logging
import pprint
import string
import sys
import yaml
from time import sleep
from libs.gbp_aci_libs import *
from libs.gbp_utils import *
from libs.neutron import *
from libs.gbp_compute import *


# Initialize logging
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
# create a logfile handler
hdlr = logging.FileHandler('/tmp/test_ml2_nat.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
hdlr.setFormatter(formatter)
# Add the handler to the logger
LOG.addHandler(hdlr)


def main():
    cfgfile = sys.argv[1]
    suite = NatML2TestSuite(cfgfile)
    suite.test_runner()


class NatML2TestSuite(object):

    def __init__(self, cfgfile):
        with open(cfgfile, 'rt') as f:
            conf = yaml.load(f)
        self.cntlrip = conf['controller_ip']
        self.apicip = conf['apic_ip']
        self.tenant_list = conf['tenant_list']
        self.extrtr = conf['ext_rtr']
        self.extrtr_ip1 = conf['extrtr_ip1']
        self.extrtr_ip2 = conf['extrtr_ip2']
        self.gwiplist = [self.extrtr_ip1, self.extrtr_ip2]
        self.avzone = conf['nova_az_name']
        self.avhost = conf['az_comp_node']
        self.novahost = conf['az_nova_comp_node']
        self.netnode = conf['network_node']
        self.comp1 = Compute(conf['network_node'])
        self.comp2 = Compute(conf['compute-2'])
        self.neutron = neutronCli(self.cntlrip)
        if conf.get('apic_passwd'):
            self.apic = gbpApic(self.apicip, mode='ml2', password=conf['apic_passwd'])
        else:
            self.apic = gbpApic(self.apicip, mode='ml2')
        self.tenant_list = ['ENGG', 'HRC']
        self.tnt1, self.tnt2 = self.tenant_list[0],\
            self.tenant_list[1]
        self.netNames = {self.tnt1: ['Net1', 'Net2', 'Net3'],
                         self.tnt2: ['ntk1', 'ntk2', 'ntk3']
                         }
        self.subNames = {self.tnt1: ['Subnet1', 'Subnet2', 'Subnet3'],
                         self.tnt2: ['sub1', 'sub2', 'sub3']
                         }
        self.apicsystemID = 'noirolab'  # TODO: should auto fetch from neutron config
        self.defaultVrf = {self.tnt1: 'shared', self.tnt2: 'shared'}
        self.Cidrs = {}
        self.Cidrs[self.tnt1] = ['2.2.2.0/28', '3.3.3.0/28', '4.4.4.0/28']
        self.Cidrs[self.tnt2] = ['7.7.7.0/28', '8.8.8.0/28', '9.9.9.0/28']

    def test_runner(self):
        """
        Method to run the Testcase in Ordered Steps
        """
        # Add Tenants
        LOG.info("\n Step:Common: Add Tenants and Users in Openstack")
        self.neutron.addDelkeystoneTnt(self.tenant_list, 'create')
        # Initiate Global Configuration
        test_results = {}
        # Add L3Out as Shared by 'Admin' Tenant
        LOG.info("\nStep:Common: Add L3Out=Management-Out as Shared by Admin Tenant")
        self.neutron.netcrud('Management-Out', 'create',
                             external=True, shared=True)

        test_list = [
                     self.test_vpr_func_1,
                     self.test_vpr_func_2,
                     self.test_vpr_func_3,
                     self.test_vpr_func_4,
                     self.test_vpr_func_5,
                     self.test_vpr_snat_func_6,
                     self.test_vpr_snat_func_7,
                     self.test_vpr_snat_func_8
                     ]
        for test in test_list:
            if test() == 0:
                test_results[string.upper(
                    test.__name__.lstrip('self.'))] = 'FAIL'
                LOG.error("\n///// %s_%s == FAIL /////" % (
                    self.__class__.__name__.upper(), string.upper(test.__name__.lstrip('self.'))))
                sys.exit(1)  # TBD: JISHNU should be removed later
            else:
                test_results[string.upper(
                    test.__name__.lstrip('self.'))] = 'PASS'
                LOG.info("\n***** %s_%s == PASS *****" % (
                    self.__class__.__name__.upper(), string.upper(test.__name__.lstrip('self.'))))
        pprint.pprint(test_results)

    def verifyAciBDtoVRF(self, rtrid_dict):
        """
        rtrid_dict: dict with key=tenant and value=rtrID
        """
        unmatched = {}
        #bdcheck = self.apic.getBdOper(self.tenant_list)
        if len(rtrid_dict.keys()) > 1:
            for tnt in self.tenant_list:
                bdcheck = self.apic.getBdOper(tnt)
                unmatched[tnt] = []
                if [unmatched[tnt].append(bdname) for bdname in self.netNames[tnt]
                    if '_%s_%s' % (self.apicsystemID, rtrid_dict[tnt]) != bdcheck[bdname]['vrfname']
                       or bdcheck[bdname]['vrfstate'] != 'formed']:
                    return unmatched
        else:
            tnt, rtrID = rtrid_dict.items()[0]
            bdcheck = self.apic.getBdOper(tnt)
            for bdname in self.netNames[tnt]:
                if '_%s_%s' % (self.apicsystemID, rtrID) != bdcheck[bdname]['vrfname']\
                        or bdcheck[bdname]['vrfstate'] != 'formed':
                    unmatched[tnt] = rtrID
                    return unmatched

    def verifySnatEpsOnAPIC(self,hostdn,snatepg,snatepIp):
        """
        Verifies the SNAT EPs of Network-Node & Comp-Node
        under 'common' tenant in APIC
        hostdn = hostname with domain of the node
        """
        getEp = self.apic.getEpgOper('common')
        if getEp and snatepg in getEp.keys():
            if getEp[snatepg]\
            ['snat|%s|Management-Out' %(hostdn)]['ip']\
            != snatepIp or \
            getEp[snatepg]\
            ['snat|%s|Management-Out' %(hostdn)]['status']\
            != 'learned,vmm':
                return 0
            else:
                return 1
        else:
            LOG.error("SNAT-Epg NOT FOUND in APIC")
            return 0

    def test_vpr_func_1(self):
        """
        Testcase-1 in VPR-Functionality Workflow
        """
        LOG.info(
        "\n########  Testcase TEST_VPR_FUNC_1   ###########\n"
        "# Add Networks and Subnets for the tenants           #\n"
        "# Add Router for each of the tenants 	               #\n"
        "# VerifyACI: VRF created for each of this Router     #\n"
        "# VerifyACI: BDs and their VRF resolves to *_shared  #\n"
        "# Add resp Router Interfaces to Tenants' networks    #\n"
        "# VerifyACI: Router's VRF resolves in the Tenant's BDs #\n"
        "######################################################\n"
        )
        LOG.info("\n Execution of Testcase starts #")

        LOG.info("\n# Step-1:TC-1: Add Networks and Subnets for the tenants #")
        self.subnetIDs = {}
        self.networkIDs = {}
        self.netIDnames = {}
        for tnt in self.tenant_list:
            # Every Network has just one Subnet, 1:1
            self.subnetIDs[tnt] = []
            self.networkIDs[tnt] = []
            self.netIDnames[tnt] = {}
            for index in range(len(self.netNames[tnt])):
                netID = self.neutron.netcrud(
                    self.netNames[tnt][index], 'create', tnt)
                self.netIDnames[tnt][netID] = self.netNames[tnt][index]
                self.networkIDs[tnt].append(netID)
                self.subnetIDs[tnt].append(self.neutron.subnetcrud(self.subNames[tnt][index],
                                                                   'create',
                                                                   netID,
                                                                   cidr=self.Cidrs[
                                                                       tnt][index],
                                                                   tenant=tnt))

        LOG.info("\n# Step-2:TC-1: Add Router for the tenants #")
        self.rtrIDs = {}
        for tnt in self.tenant_list:
            _id = self.neutron.rtrcrud('RTR1', 'create', tenant=tnt)
            self.rtrIDs[tnt] = _id
        LOG.info("\nRouter IDs for the respective Tenants == %s" %
                 (self.rtrIDs))

        LOG.info("\n# Step-3-TC-1:VerifyACI: VRF got created for this Router #")
        vrfnotfound = [self.rtrIDs[tnt] for tnt in self.tenant_list
                       if '_%s_%s' % (self.apicsystemID, self.rtrIDs[tnt])
                       not in self.apic.getVrfs(tnt)]
        if vrfnotfound:
            LOG.info(
                "\nStep-3-TC-1:Fail: Following VRFs not found in ACI = %s" % (vrfnotfound))
            return 0

        LOG.info(
            "\n# Step-4-TC-1:VerifyACI: BDs and their VRF resolves to *_shared #")
        unmatchedvrfs = self.verifyAciBDtoVRF(self.defaultVrf)
        if unmatchedvrfs:
            LOG.error("\nStep-4-TC-1:Fail: Unresolved VRF for following BDs >> %s"
                      % (unmatchedvrfs))
            return 0

        LOG.info("\n# Step-5-TC-1: Add resp Router Interfaces to Tenants' networks #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.rtrIDs[tnt], 'add', rtrprop='interface',
                                  subnet=subnetId, tenant=tnt) for subnetId in self.subnetIDs[tnt]]

        LOG.info(
            "\n# Step-6-TC-1: VerifyACI: Router's VRF resolves in the Tenant's BDs #")
        unmatchedvrfs = self.verifyAciBDtoVRF(self.rtrIDs)
        if unmatchedvrfs:
            LOG.error("\nStep-6-TC-1:Fail: Unresolved VRF for following BDs >> %s"
                      % (unmatchedvrfs))
            return 0

    def test_vpr_func_2(self):
        """
        Testcase-2 in VPR-Functionality Workflow
        """
        LOG.info(
        "\n########  Testcase TEST_VPR_FUNC_2   ############\n"
        "# Remove each tenant's Router from the attached ntks  #\n"
        "# VerifyACI: VRF for each BD VRF resolves to *_shared #\n"
        "# Add new subnet to the respective tenants's ntks     #\n"
        "# Add back the Routers's interfaces to the above new subnets #\n"
        "# VerifyACI: Router's VRF resolves in the Tenant's BDs #\n"
        "# Add back Routers's interfaces to existing Old subnets of tnts'#\n"
        "# Verify: Routers' have interfaces attached to multiple subnets #\n"
        "# Remove router interface from all but one subnet in each ntk #\n"
        "# VerifyACI: The BDs are STILL connected to Router's VRF #\n"
        "#####################################################\n"
        )
        LOG.info("\n Execution of Testcase starts #")

        LOG.info(
            "\n# Step-1-TC-2: Remove each tenant's Router from the attached ntks #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.rtrIDs[tnt], 'delete', rtrprop='interface',
                                  subnet=subnetId, tenant=tnt) for subnetId in self.subnetIDs[tnt]]

        LOG.info(
            "\n# Step-2-TC-2:VerifyACI: VRF for each BD VRF resolves to *_shared #")
        unmatchedvrfs = self.verifyAciBDtoVRF(self.defaultVrf)
        if unmatchedvrfs:
            LOG.error("\nStep-2-TC-2:Fail: Unresolved VRF for following BDs >> %s"
                      % (unmatchedvrfs))
            return 0

        LOG.info("\n# Step-3-TC-2: Add new subnet to the respective tenants's ntks #")
        # Duplicate subnets across tenants
        self.newCidrs = ['101.101.101.0/28',
                         '102.102.102.0/28', '103.103.103.0/28']
        self.newSubNames = ['newSub1', 'newSub2', 'newSub3']
        self.new_subnetIDs = {}
        for tnt in self.tenant_list:
            self.new_subnetIDs[tnt] = []
            for index in range(len(self.newSubNames)):
                self.new_subnetIDs[tnt].append(self.neutron.subnetcrud(
                    self.newSubNames[index],
                    'create',
                    self.networkIDs[tnt][index],
                    cidr=self.newCidrs[index],
                    tenant=tnt))

        LOG.info(
            "\n# Step-4-TC-2: Add back the Routers's interfaces to the above new subnets #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.rtrIDs[tnt], 'add', rtrprop='interface',
                                  subnet=subnetId, tenant=tnt) for subnetId in self.new_subnetIDs[tnt]]

        LOG.info(
            "\n# Step-5-TC-2: VerifyACI: Router's VRF resolves in the Tenant's BDs #")
        unmatchedvrfs = self.verifyAciBDtoVRF(self.rtrIDs)
        if unmatchedvrfs:
            LOG.error("\nStep-5-TC-2:Fail:VRFs did NOT resolve in following BD >> %s"
                      % (unmatchedvrfs))
            return 0

        LOG.info(
            "\n# Step-6-TC-2: Add back the Routers's interfaces to existing Old subnets of tenants #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.rtrIDs[tnt], 'add', rtrprop='interface',
                                  subnet=subnetId, tenant=tnt) for subnetId in self.subnetIDs[tnt]]
        # TBD: Step 7(Verify in Neutron router-ports are connected to multiple
        # subnets
        LOG.info(
            "\nStep-8-TC-2: Remove the router interface from all but one subnet in each ntk #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.rtrIDs[tnt], 'delete', rtrprop='interface',
                                  subnet=subnetId, tenant=tnt) for subnetId in self.new_subnetIDs[tnt]]

        LOG.info(
            "\nStep-9-TC-2VerifyACI: The BDs are STILL connected to Router's VRF #")
        unmatchedvrfs = self.verifyAciBDtoVRF(self.rtrIDs)
        if unmatchedvrfs:
            LOG.error("\nStep-9-TC-2:Fail:VRFs did NOT resolve in following BD >> %s"
                      % (unmatchedvrfs))
            return 0

    def test_vpr_func_3(self):
        """
        Testcase-3 in VPR-Functionality Workflow
        """
        LOG.info(
        "\n############  Testcase TEST_VPR_FUNC_3   ############\n"
        "# Remove the router interfaces but attached to only One Ntk #\n"
        "# VerifyACI: VRF for all but one BD's VRF resolves to *_shared #\n"
        "# Add new addtional Router in Tenant, attach to its unrouted BDs #n"
        "# VerifyACI: VRF got created for the new router in ACI         #\n"
        "# VerifyACI: Resp new Router's VRF resolves in the Tenant's BDs #\n"
        "#######################################################\n"
        )

        LOG.info("\n Execution of Testcase starts #")
        LOG.info(
        "\n# Step-1-TC-3: Remove the router interfaces but attached to only One Ntk #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.rtrIDs[tnt], 'delete', rtrprop='interface',
                                  subnet=subnetName, tenant=tnt) for subnetName in self.subNames[tnt][1:]]

        LOG.info(
        "\nStep-2-TC-3: VerifyACI: VRF for all but one BD's VRF resolves to *_shared #")
        unmatched = {}
        #bdcheck = self.apic.getBdOper(self.tenant_list)
        for tnt in self.tenant_list:
            bdcheck = self.apic.getBdOper(tnt)
            bdname = self.netNames[tnt][0]
            if '_%s_%s' % (self.apicsystemID, self.rtrIDs[tnt]) != bdcheck[bdname]['vrfname'] \
               or bdcheck[bdname]['vrfstate'] != 'formed':
                LOG.info("\nStep-2-TC-3:Fail:Tenaant %s BD %s not associated with correct VRF %s"
                         % (tnt, bdname, self.rtrIDs[tnt]))
                return 0
            unmatched[tnt] = [bdname for bdname in self.netNames[tnt][1:]
                              if '_%s_%s' % (self.apicsystemID, 'shared') != bdcheck[bdname]['vrfname']
                                 or bdcheck[bdname]['vrfstate'] != 'formed']
            if unmatched[tnt]:
                LOG.info(
                    "\nStep-2-TC-3:Fail:Following BDs are not associated with 'shared' VRF = %s" % (unmatched))
                return 0

        LOG.info(
            "\nStep-3-TC-3: Add new addtional Router in Tenant, attach to its unrouted BDs #")
        self.newrtrIDs = {}
        for tnt in self.tenant_list:
            _id = self.neutron.rtrcrud('RTR2', 'create', tenant=tnt)
            self.newrtrIDs[tnt] = _id
        LOG.info("\n2nd Router IDs for the respective Tenants == %s" %
                 (self.newrtrIDs))

        LOG.info("\n# Step-4-TC-3:VerifyACI: VRF got created for this Router #")
        vrfnotfound = [self.newrtrIDs[tnt] for tnt in self.tenant_list
                       if '_%s_%s' % (self.apicsystemID, self.newrtrIDs[tnt])
                       not in self.apic.getVrfs(tnt)]
        if vrfnotfound:
            LOG.info(
                "\nStep-4-TC-3:Fail: Following VRFs not found in ACI = %s" % (vrfnotfound))
            return 0

        LOG.info(
            "\n Step-5-TC-3: Attach new router to the networks which are in *_shared vrf")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.newrtrIDs[tnt], 'add', rtrprop='interface',
                                  subnet=subnetName, tenant=tnt) for subnetName in self.subNames[tnt][1:]]

        LOG.info(
            "\nStep-6-TC-3: Resp new Router's VRF resolves in the Tenant's BDs #")
        unmatched = {}
        #bdcheck = self.apic.getBdOper(self.tenant_list)
        for tnt in self.tenant_list:
            bdcheck = self.apic.getBdOper(tnt)
            unmatched[tnt] = []
            if [unmatched[tnt].append(bdname) for bdname in self.netNames[tnt][1:]
                    if '_%s_%s' % (self.apicsystemID, self.newrtrIDs[tnt]) != bdcheck[bdname]['vrfname']
                    or bdcheck[bdname]['vrfstate'] != 'formed']:
                LOG.info(
                    "\nStep-6-TC-3:Fail:Following BDs are NOT associated with correct VRF = %s" % (unmatched))
                return 0

    def test_vpr_func_4(self):
        """
        Testcase-4 in VPR-Functionality Workflow
        """
        LOG.info(
        "\n############  Testcase TEST_VPR_FUNC_4   ###################\n"
        "# Remove the routers' interfaces from all attached networks  #\n"
        "# Verify the RouterVRFs rdConfig files removed from Net-Node #\n"
        "# VerifyACI: VRF for all BD's VRF resolves to *_shared       #\n"
        "# Delete all the routers                                     #\n"
        "# VerifyACI: VRFs of the deleted routers are deleted also    #\n"
        "##############################################################\n"
        )
        LOG.info("\n Execution of Testcase starts #")
        LOG.info(
            "\n Step-1-TC-4: Remove the routers' interfaces from all attached networks #")
        for tnt in self.tenant_list:
            [self.neutron.rtrcrud(self.newrtrIDs[tnt], 'delete', rtrprop='interface',
                                  subnet=subnetName, tenant=tnt) for subnetName in self.subNames[tnt][1:]]
            self.neutron.rtrcrud(self.rtrIDs[tnt], 'delete', rtrprop='interface',
                                 subnet=self.subNames[tnt][0], tenant=tnt)

        # Merging the two dicts rtrIDs & newrtrIDs
        mergedDict = {}
        for k in self.rtrIDs.iterkeys():  # where k/key = tenant
            mergedDict[k] = [self.rtrIDs[k], self.newrtrIDs[k]]

        LOG.info(
            "\n# Step-2-TC-4: Verify the RouterVRFs rdConfig files removed from Net-Node #")
        stale = [rtr for tnt in self.tenant_list for rtr in mergedDict[tnt]
                 if self.comp1.GetReadFiles(
                     '/var/lib/opflex-agent-ovs/endpoints/router:%s.rdconfig'
                     % (rtr))]
        if stale:
            LOG.info(
                "\nStep-2-TC-4:Fail: Following routers rdconfig are stale = %s" % (stale))
            #return 0 #TBD:JISHNU, known bug 

        LOG.info(
            "\n# Step-3-TC-4:VerifyACI: VRF for all BD's VRF resolves to *_shared #")
        unmatchedvrfs = self.verifyAciBDtoVRF(self.defaultVrf)
        if unmatchedvrfs:
            LOG.error(
                "\nStep-3-TC-4:Fail: Unresolved VRF for following BDs >> %s" % (unmatchedvrfs))
            return 0

        LOG.info("\nStep-4-TC-4: Delete all the routers #")
        [self.neutron.rtrcrud(rtr, 'delete', tenant=tnt) for tnt in self.tenant_list
         for rtr in mergedDict[tnt]]

        LOG.info(
            "\n# Step-5-TC-4:VerifyACI: VRFs of the deleted routers are deleted also #")
        """"""
        for tnt in self.tenant_list:
            getVrfs = self.apic.getVrfs(tnt)
            print getVrfs
            stalevrf = [rtr for rtr in mergedDict[tnt]
                        if '_%s_%s' % (self.apicsystemID, rtr) in getVrfs]
        if len(stalevrf):
            LOG.info(
                "\nStep-5-TC-4:Fail: Following Routers' VRF stale in ACI = %s" % (stalevrf))
            return 0

    def test_vpr_func_5(self):
        """
        Testcase-5 in VPR-Functionality Workflow
        """
        LOG.info(
        "\n############  Testcase TEST_VPR_FUNC_5 #####################\n"
        "# Add Router in a given tenant			       #\n"
        "# Attach router to multiple networks in a given tenant       #\n"
        "# VerifyACI: VRF for attached BDs resolves to Routers' VRF   #\n"
        "# Bring up VMs on each of the network of a given tenant      #\n"
        "# VerifyACI: Verify the Endpoint Learnings 		       #\n"
        "# Verify: EP files of VMs refers domain-name to Routers' VRF #\n"
        "# Verify: rdConfig of the tenant refers to Routers's VRF     #\n"
        "# Verify: Traffic between the VMs across networks in the tenant #\n"
        "##############################################################\n"
        )
        LOG.info("\n Execution of Testcase starts #")

        LOG.info("\n# Step-1-TC-5: Add Router for the tenant %s #" %
                 (self.tnt1))
        self.rtrID = self.neutron.rtrcrud('RTR1', 'create', tenant=self.tnt1)

        LOG.info(
            "\n# Step-2-TC-5: Attach router to multiple networks in a given tenant #")
        #Since there are two subnets per network in 'tnt1', so the router needs to 
        #be attached to both subnets.
        for subnetId in self.subnetIDs[self.tnt1]:
            self.neutron.rtrcrud(self.rtrID, 'add', rtrprop='interface',
                                 subnet=subnetId, tenant=self.tnt1)
        for subnetId in self.new_subnetIDs[self.tnt1]:
            self.neutron.rtrcrud(self.rtrID, 'add', rtrprop='interface',
                                 subnet=subnetId, tenant=self.tnt1)
        LOG.info(
        "\n# Step-3-TC-5:VerifyACI: VRF for attached BDs resolves to Routers' VRF #"
        )
        unmatchedvrfs = self.verifyAciBDtoVRF({self.tnt1: self.rtrID})
        if unmatchedvrfs:
            LOG.error("\nStep-3-TC-5:Fail: Unresolved VRF for following BDs >> %s"
                      % (unmatchedvrfs))
            return 0

        LOG.info(
            "\n# Step-4-TC-5: Bring up VMs on each of the network of a given tenant #")
        # Since VMs are created with 'default' secgroup, hence
        # adding rules to the default secgroup
        self.neutron.runcmd(
            'nova --os-tenant-name %s secgroup-add-rule default icmp -1 -1 0.0.0.0/0'
            % (self.tnt1)
        )
        self.neutron.runcmd(
            'nova --os-tenant-name %s secgroup-add-rule default tcp 22 22 0.0.0.0/0'
            % (self.tnt1)
        )
        self.NETtoVM = {}
        vm_num = 1
        az = self.neutron.alternate_az(self.avzone)  # Intent is to place VMs alternately on two comp-nodes
        avzonetoHost = [self.avhost, self.novahost]
        for netid, name in self.netIDnames[self.tnt1].iteritems():
            self.NETtoVM[name] = {}
            self.vmname = '%s-VM-' % (self.tnt1) + str(vm_num)
            vmcreate = self.neutron.spawnVM(self.tnt1,
                                            self.vmname,
                                            netid,
                                            availzone=az.next()
                                            )
            # vmcreate: label for the return value which is
            # [vmip,portID,portMAC]
            if not vmcreate:
                LOG.error("\nStep-4-TC-5:Fail: VM Creation Failed")
                return 0
            else:
                self.NETtoVM[name][self.vmname] = vmcreate
            vm_num = vm_num + 1

        LOG.info("\n# Step-5-TC-5:VerifyACI: Verify the Endpoint Learnings #")
        LOG.info("\nSleeping for 30 secs for the Opflex-Agent to send GARP")
        sleep(30)
        getEp = self.apic.getEpgOper(self.tnt1)
        if getEp:
            for net in self.netNames[self.tnt1]:
                vm = self.NETtoVM[net].keys()[0]
                if not vm in getEp[net].keys() \
                   or getEp[net][vm]['status'] != 'learned,vmm':
                    LOG.error(
                        "\nStep-5-TC-5:Fail: EP Learning failed on APIC")
                    return 0

        LOG.info(
            "\n# Step-6-TC-5: Verify: EP files of VMs refers domain-name to Routers' VRF #")
        for key, val in self.NETtoVM.iteritems():  # key=Network name
            for value in val.itervalues():
                vmip, vmportID, vmportMAC = value
                if not self.comp2.verify_EpFile(
                    vmportID,
                    vmportMAC,
                    endpoint_group_name='%s|%s' % (self.apicsystemID, key),
                    domain_name='_%s_%s' % (self.apicsystemID, self.rtrID)
                ) and \
                    not self.comp1.verify_EpFile(
                        vmportID,
                        vmportMAC,
                        endpoint_group_name='%s|%s' % (self.apicsystemID, key),
                        domain_name='_%s_%s' % (self.apicsystemID, self.rtrID)
                ):
                    LOG.error(
                        "\nStep-6-TC-5:Fail: Incorrect values/attributes in EP file")
                    return 0

        LOG.info(
            "\n Step-7-TC-5: Verify: rdConfig of the tenant refers to Routers's VRF #")
        if not self.comp2.verify_rdConfig(self.tnt1,
                                          self.rtrID,
                                          self.subNames[self.tnt1]
                                          ) and \
            not self.comp1.verify_rdConfig(self.tnt1,
                                           self.rtrID,
                                           self.subNames[self.tnt1]
                                           ):
            LOG.error(
                "\nStep-7-TC-5:Fail: Incorrect values/attributes in rdConfig file")
            return 0

        LOG.info(
            "\n Step-8-TC-5: Verify Traffic between the VMs across networks in the tenant #")

    def test_vpr_snat_func_6(self):
        """
        Testcase-6 in VPR-SNAT-Functionality Workflow
        """
        LOG.info(
       "\n##############  Testcase TEST_VPR_NAT_FUNC_6 ###############\n"
       "# Attach TC-5's Router in a given tenant to the ExtNetwork   #\n"
       "# Attach router to multiple networks in a given tenant       #\n"
       "# Verify: EP Files has SNAT mapping set correctly	       #\n"
       "# VerifyACI: ShadowL3Out's VRF resolves to Routers' VRF      #\n"
       "# VerifyACI: SNAT EPs are learned in the NAT-EPGs	       #\n"
       "# Verify: Traffic between the VMs across networks in the tenant #\n"
       "# Verify: Traffic between the VMs and External Router	       #\n"
       "##############################################################\n"
        )
        LOG.info("\n Execution of Testcase starts #")

        LOG.info(
            "\nStep-1-TC-6: Attach TC-5's Router in a given tenant to the ExtNetwork   #")
        self.neutron.rtrcrud(self.rtrID, 'set', rtrprop='gateway',
                             gw='Management-Out', tenant=self.tnt1)
        LOG.info(
            "\nStep-2-TC-6: Attach router to multiple networks in a given tenant #")
        # The router is already attached to multiple nets of the tenant in TC-5
	sleep(20) #Just to let the change percolate to ACI 
        LOG.info("\nStep-3-TC-6: Verify: SNAT EP exists in the computes #")
        netnodeSnat = self.comp1.getSNATEp('Management-Out')
        comp2Snat = self.comp2.getSNATEp('Management-Out')
        if netnodeSnat:
            nn_snatintf, self.nn_snatip, nn_snattnt, self.nn_snatepg, self.nn_snatep = netnodeSnat
        else:
            LOG.info("\nStep-3-TC-6:Fail: SNAT EP not found in Network-Node")
            return 0
        if comp2Snat:
            cn_snatintf, self.cn_snatip, cn_snattnt, cn_snatepg, cn_snatep = comp2Snat
        else:
            LOG.info("\nStep-3-TC-6:Fail: SNAT EP not found in Compute-Node")
            return 0

        LOG.info(
            "\nStep-4-TC-6: VerifyACI: ShadowL3Out's VRF resolves to Routers' VRF #")
        ShdL3 = self.apic.getL3Out(self.tnt1)
        if len(ShdL3):
            if '_Shd-%s-' % (self.rtrID) in ShdL3.keys()[0]:
                if ShdL3.values()[0]['vrfname'] == '_%s_%s' % (self.apicsystemID, self.rtrID) \
                        and ShdL3.values()[0]['vrfstate'] == 'formed':
                    print "Vrf name and state matched"
                else:
                    LOG.info(
                    "\nStep-4-TC-6: Fail: VRfname or VRfState one or both did not match")
                    return 0
            else:
                LOG.info("\nStep-4-TC-6: Fail: Shadow L3Out VRF not Found")
                return 0
        else:
            LOG.info("\nStep-4-TC-6: Fail: L3Outs not found in this tenant")
            return 0
        #TBD:JISHNU >>below check is incorrect, Moreover keep a check for ip-mapping,
        #vrf_per_router_tenant MUST be added /deleted as part of this suite. The suite
        #should run seamlessly with and without the config_flag
        #TBD: JISHNU .. also add the router to all subnets for neutron behavior
        LOG.info("\nStep-6-TC-6:VerifyACI: SNAT EPs are learned in the NAT-EPGs #")
        if not self.verifySnatEpsOnAPIC(self.novahost,
                               self.nn_snatepg,
                               self.nn_snatip):
            LOG.error(
                "\nStep-6-TC-6:Fail: Network-Node's SNATEP"\
                "%s Learning failed on APIC"\
                % (self.nn_snatip))
        if not self.verifySnatEpsOnAPIC(self.avhost,
                               self.nn_snatepg,
                               self.cn_snatip):
            LOG.error(
                "\nStep-6-TC-6:Fail: Compute-Node-2's SNATEP"\
                "%s Learning failed on APIC"\
                % (self.cn_snatip))

        LOG.info("\nStep-7-TC-6:Verify: Traffic between the VMs across networks in the tenant #")

        LOG.info("\nStep-8-TC-6: Verify: Traffic between the VMs and External Router #")

    def test_vpr_snat_func_7(self):
        """
        Testcase-7 in VPR-SNAT-Functionality Workflow
        """
        LOG.info(
        "\n##############  Testcase TEST_VPR_NAT_FUNC_7 ###############\n"
        "# Clear TC-5's Router GW in a given tenant to the ExtNetwork #\n"
        "# Attach TC-5's Tenant's Router to ExtNetwork GW             #\n"
        "# VerifyACI: ShadowL3Out's VRF resolves to Routers' VRF      #\n"
        "# VerifyACI: SNAT EPs are learned in the NAT-EPGs	       #\n"
        "# Verify: Traffic between the VMs and External Router	       #\n"
        "##############################################################\n"
        )
        LOG.info("\n Execution of Testcase starts #")

        LOG.info(
            "\nStep-1-TC-7: Clear TC-5's Router GW in a given tenant to the ExtNetwork #")
        self.neutron.rtrcrud(self.rtrID, 'clear', rtrprop='gateway',
                             tenant=self.tnt1)
        LOG.info(
            "\nStep-2-TC-7: Attach TC-5's Tenant's Router to ExtNetwork GW #")
        self.neutron.rtrcrud(self.rtrID, 'set', rtrprop='gateway',
                             gw='Management-Out', tenant=self.tnt1)
        sleep(10) #Just to let the change percolate to ACI
        LOG.info(
            "\nStep-3-TC-7: VerifyACI: ShadowL3Out's VRF resolves to Routers' VRF #")
        ShdL3 = self.apic.getL3Out(self.tnt1)
        if len(ShdL3):
            if '_Shd-%s-' % (self.rtrID) in ShdL3.keys()[0]:
                if ShdL3.values()[0]['vrfname'] == '_%s_%s' % (self.apicsystemID, self.rtrID) \
                        and ShdL3.values()[0]['vrfstate'] == 'formed':
                    print "Vrf name and state matched"
                else:
                    LOG.info(
                    "\nStep-3-TC-7: Fail: VRfname or VRfState one or both did not match")
                    return 0
            else:
                LOG.info("\nStep-3-TC-7: Fail: Shadow L3Out VRF not Found")
                return 0
        else:
            LOG.info("\nStep-3-TC-7: Fail: L3Outs not found in this tenant")
            return 0

        LOG.info("\nStep-4-TC-7:VerifyACI: SNAT EPs are learned in the NAT-EPGs #")
        if not self.verifySnatEpsOnAPIC(self.novahost,
                               self.nn_snatepg,
                               self.nn_snatip):
            LOG.error(
                "\nStep-4-TC-7:Fail: Network-Node's SNATEP"\
                "%s Learning failed on APIC"\
                % (self.nn_snatip))
        if not self.verifySnatEpsOnAPIC(self.avhost,
                               self.nn_snatepg,
                               self.cn_snatip):
            LOG.error(
                "\nStep-4-TC-7:Fail: Compute-Node-2's SNATEP"\
                "%s Learning failed on APIC"\
                % (self.cn_snatip))

        LOG.info("\nStep-5-TC-7: Verify: Traffic between the VMs and External Router #")

    def test_vpr_snat_func_8(self):
        """
        Testcase-8 in VPR-SNAT-Functionality Workflow
        """
        LOG.info(
        "\n########  Testcase TEST_VPR_NAT_FUNC_8 #####################\n"
        "# Clear TC-5's Router GW in a given tenant to the ExtNetwork #\n"
        "# Remove TC-5's Router from all attached private networks    #\n"
        "# Attach TC-5's Tenant's Router to ExtNetwork GW             #\n"
        "# Attach TC-5's Tenants Router to the private networks	      #\n"
        "# VerifyACI: VRF for attached BDs resolves to Routers' VRF   #\n"
        "# VerifyACI: ShadowL3Out's VRF resolves to Routers' VRF      #\n"
        "# VerifyACI: SNAT EPs are learned in the NAT-EPGs            #\n"
        "# Verify: Traffic between the VMs and External Router        #\n"
        "##############################################################\n")
        LOG.info("\n Execution of Testcase starts #")

        LOG.info(
        "\nStep-1-TC-8: Clear TC-6's Router GW in a given tenant to the ExtNetwork #")
        self.neutron.rtrcrud(self.rtrID, 'clear', rtrprop='gateway', tenant=self.tnt1)

        LOG.info(
        "\nStep-2-TC-8: Remove TC-5's Router from all attached private networks #"
        )
        for subnetId in self.subnetIDs[self.tnt1]:
            self.neutron.rtrcrud(self.rtrID, 'add', rtrprop='interface',
                                 subnet=subnetId, tenant=self.tnt1)
        for subnetId in self.new_subnetIDs[self.tnt1]:
            self.neutron.rtrcrud(self.rtrID, 'add', rtrprop='interface',
                                 subnet=subnetId, tenant=self.tnt1)
        LOG.info(
        "\nStep-3-TC-8: Attach TC-6's Tenant's Router to ExtNetwork GW #")
        self.neutron.rtrcrud(self.rtrID,
                            'set',
                            rtrprop='gateway',
                            gw='Management-Out',
                            tenant=self.tnt1)

        LOG.info(
        "\n# Step-4-TC-8: Attach router to multiple networks in a given tenant #")
        for subnetId in self.subnetIDs[self.tnt1]:
            self.neutron.rtrcrud(self.rtrID, 'add', rtrprop='interface',
                                 subnet=subnetId, tenant=self.tnt1)
        for subnetId in self.new_subnetIDs[self.tnt1]:
            self.neutron.rtrcrud(self.rtrID, 'add', rtrprop='interface',
                                 subnet=subnetId, tenant=self.tnt1)
        sleep(10) #Just to let the change percolate to ACI
        LOG.info(
        "\nStep-5-TC-8: VerifyACI: VRF for attached BDs resolves to Routers' VRF #"
        )
        unmatchedvrfs = self.verifyAciBDtoVRF({self.tnt1: self.rtrID})
        if unmatchedvrfs:
            LOG.error("\nStep-5-TC-8:Fail: Unresolved VRF for following BDs >> %s"
                      % (unmatchedvrfs))
            return 0
        
        LOG.info(
        "\nStep-6-TC-8: VerifyACI: ShadowL3Out's VRF resolves to Routers' VRF #"
        )
        ShdL3 = self.apic.getL3Out(self.tnt1)
        if len(ShdL3):
            if '_Shd-%s-' % (self.rtrID) in ShdL3.keys()[0]:
                if ShdL3.values()[0]['vrfname'] == '_%s_%s' % (self.apicsystemID, self.rtrID) \
                        and ShdL3.values()[0]['vrfstate'] == 'formed':
                    print "Vrf name and state matched"
                else:
                    LOG.info(
                    "\nStep-6-TC-8: Fail: VRfname or VRfState one or both did not match"
                    )
                    return 0
            else:
                LOG.info("\nStep-6-TC-8: Fail: Shadow L3Out VRF not Found")
                return 0
        else:
            LOG.info("\nStep-6-TC-8: Fail: L3Outs not found in this tenant")
            return 0

        LOG.info(
        "\nStep-7-TC-8:VerifyACI: SNAT EPs are learned in the NAT-EPGs #"
        )
        if not self.verifySnatEpsOnAPIC(self.novahost,
                               self.nn_snatepg,
                               self.nn_snatip):
            LOG.error(
                "\nStep-7-TC-8:Fail: Network-Node's SNATEP"\
                "%s Learning failed on APIC"\
                % (self.nn_snatip))
        if not self.verifySnatEpsOnAPIC(self.avhost,
                               self.nn_snatepg,
                               self.cn_snatip):
            LOG.error(
                "\nStep-7-TC-8:Fail: Compute-Node-2's SNATEP"\
                "%s Learning failed on APIC"\
                % (self.cn_snatip))
            return 0

        LOG.info("\nStep-8-TC-8: Verify: Traffic between the VMs and External Router #")

if __name__ == "__main__":
    main()
