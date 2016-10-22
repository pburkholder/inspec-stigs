# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-RG-000002 - Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key.'

control 'WN12-RG-000002' do
  impact 1.0
  title 'Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key.'
  desc '
Permissions on the Active Setup\Installed Components registry key must only allow privileged accounts to add or change registry values.  If standard user accounts have this capability, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.
'
  tag 'stig','WN12-RG-000002'
  tag severity: 'high'
  tag checkid: 'C-WN12-RG-000002_chk'
  tag fixid: 'F-WN12-RG-000002_fix'
  tag version: 'WN12-RG-000002'
  tag ruleid: 'WN12-RG-000002_rule'
  tag fixtext: '
Ensure only Read permissions are assigned to standard user accounts and groups for the following registry keys. The default configuration satisfies this requirement.
All systems:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components
64-bit systems:
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components
'
  tag checktext: '
Navigate to the following registry key and review the assigned permissions:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components

On 64-bit systems, also review the permissions assigned to the following registry key:
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components 

Verify standard user accounts and groups only have Read permissions to this registry key.  If any standard user accounts or groups have greater permissions, this is a finding. The default permissions satisfy this requirement.
'

# START_DESCRIBE WN12-RG-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-RG-000002

end
