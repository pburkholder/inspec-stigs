# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000005 - Domain users must be required to elevate when setting a network\'s location.'

control 'WN12-CC-000005' do
  impact 0.1
  title 'Domain users must be required to elevate when setting a network\'s location.'
  desc '
Selecting an incorrect network location may allow greater exposure of a system.  Elevation is required by default on nondomain systems to change network location.  This setting configures elevation to also be required on domain-joined systems.
'
  tag 'stig','WN12-CC-000005'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000005_chk'
  tag fixid: 'F-WN12-CC-000005_fix'
  tag version: 'WN12-CC-000005'
  tag ruleid: 'WN12-CC-000005_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Require domain users to elevate when setting a network\'s location" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Network Connections\

Value Name: NC_StdDomainUserSetLocation

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000005
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000005

end
