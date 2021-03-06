# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000118 - Nonadministrators must be prevented from applying vendor-signed updates.'

control 'WN12-CC-000118' do
  impact 0.1
  title 'Nonadministrators must be prevented from applying vendor-signed updates.'
  desc '
Uncontrolled system updates can introduce issues to a system.  This setting will prevent users from applying vendor-signed updates (though they may be from a trusted source).
'
  tag 'stig','WN12-CC-000118'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000118_chk'
  tag fixid: 'F-WN12-CC-000118_fix'
  tag version: 'WN12-CC-000118'
  tag ruleid: 'WN12-CC-000118_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prohibit non-administrators from applying vendor signed updates" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: DisableLUAPatching

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000118
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000118

end
