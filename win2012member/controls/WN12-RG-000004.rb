# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-RG-000004 - Anonymous access to the registry must be restricted.'

control 'WN12-RG-000004' do
  impact 1.0
  title 'Anonymous access to the registry must be restricted.'
  desc '
The registry is integral to the function, security, and stability of the Windows system.  Some processes may require anonymous access to the registry.  This must be limited to properly protect the system.
'
  tag 'stig','WN12-RG-000004'
  tag severity: 'high'
  tag checkid: 'C-WN12-RG-000004_chk'
  tag fixid: 'F-WN12-RG-000004_fix'
  tag version: 'WN12-RG-000004'
  tag ruleid: 'WN12-RG-000004_rule'
  tag fixtext: '
Ensure the system is configured to prevent anonymous users from gaining access to the registry.  Maintain the default permissions of the following registry key:

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\ 

Administrators - Full 
Backup Operators - Read(QENR) 
Local Service - Read
'
  tag checktext: '
Using the Registry Editor, navigate to the following key: 

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\ 

If the key does not exist, this is a finding. If the permissions are not at least as restrictive as the defaults listed below, this is a finding.

Administrators - Full 
Backup Operators - Read(QENR) 
Local Service - Read
'

# START_DESCRIBE WN12-RG-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-RG-000004

end
