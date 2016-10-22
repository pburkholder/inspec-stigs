# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000004 - Network Bridges must be prohibited in Windows.'

control 'WN12-CC-000004' do
  impact 0.5
  title 'Network Bridges must be prohibited in Windows.'
  desc '
A Network Bridge can connect two or more network segments, allowing unauthorized access or exposure of sensitive data.  This setting prevents a Network Bridge from being installed and configured.
'
  tag 'stig','WN12-CC-000004'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000004_chk'
  tag fixid: 'F-WN12-CC-000004_fix'
  tag version: 'WN12-CC-000004'
  tag ruleid: 'WN12-CC-000004_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Prohibit installation and configuration of Network Bridge on your DNS domain network" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Network Connections\

Value Name: NC_AllowNetBridge_NLA

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000004

end
