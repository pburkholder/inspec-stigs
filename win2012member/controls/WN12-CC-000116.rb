# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000116 - The Windows Installer Always install with elevated privileges option must be disabled.'

control 'WN12-CC-000116' do
  impact 1.0
  title 'The Windows Installer Always install with elevated privileges option must be disabled.'
  desc '
Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.
'
  tag 'stig','WN12-CC-000116'
  tag severity: 'high'
  tag checkid: 'C-WN12-CC-000116_chk'
  tag fixid: 'F-WN12-CC-000116_fix'
  tag version: 'WN12-CC-000116'
  tag ruleid: 'WN12-CC-000116_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Always install with elevated privileges" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: AlwaysInstallElevated

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000116
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000116

end
