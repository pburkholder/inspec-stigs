# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-RG-000001 - Standard user accounts must only have Read permissions to the Winlogon registry key.'

control 'WN12-RG-000001' do
  impact 1.0
  title 'Standard user accounts must only have Read permissions to the Winlogon registry key.'
  desc '
Permissions on the Winlogon registry key must only allow privileged accounts to change registry values.  If standard users have this capability, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.
'
  tag 'stig','WN12-RG-000001'
  tag severity: 'high'
  tag checkid: 'C-WN12-RG-000001_chk'
  tag fixid: 'F-WN12-RG-000001_fix'
  tag version: 'WN12-RG-000001'
  tag ruleid: 'WN12-RG-000001_rule'
  tag fixtext: '
Ensure only Read permissions are assigned to standard user accounts and groups for the following registry key. The default configuration satisfies this requirement.
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
'
  tag checktext: '
Navigate to the following registry key and review the assigned permissions:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

Standard user accounts and groups must only have Read permissions to this registry key.  If any standard user accounts or groups have greater permissions, this is a finding.  The default permissions satisfy this requirement.
'

# START_DESCRIBE WN12-RG-000001
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-RG-000001

end
