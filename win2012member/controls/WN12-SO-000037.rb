# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000037 - IPv6 source routing must be configured to the highest protection level.'

control 'WN12-SO-000037' do
  impact 0.1
  title 'IPv6 source routing must be configured to the highest protection level.'
  desc '
Configuring the system to disable IPv6 source routing protects against spoofing.
'
  tag 'stig','WN12-SO-000037'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000037_chk'
  tag fixid: 'F-WN12-SO-000037_fix'
  tag version: 'WN12-SO-000037'
  tag ruleid: 'WN12-SO-000037_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: DisableIpSourceRouting

Type: REG_DWORD
Value: 2
'

# START_DESCRIBE WN12-SO-000037
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000037

end
