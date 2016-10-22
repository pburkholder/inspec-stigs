# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000044 - The system must be configured to disable the Internet Router Discovery Protocol (IRDP).'

control 'WN12-SO-000044' do
  impact 0.1
  title 'The system must be configured to disable the Internet Router Discovery Protocol (IRDP).'
  desc '
The Internet Router Discovery Protocol (IRDP) is used to detect and configure default gateway addresses on the computer.  If a router is impersonated on a network, traffic could be routed through the compromised system.
'
  tag 'stig','WN12-SO-000044'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000044_chk'
  tag fixid: 'F-WN12-SO-000044_fix'
  tag version: 'WN12-SO-000044'
  tag ruleid: 'WN12-SO-000044_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" to "Disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: PerformRouterDiscovery

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000044
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000044

end
