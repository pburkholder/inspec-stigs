# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000115 - Users must be prevented from changing installation options.'

control 'WN12-CC-000115' do
  impact 0.5
  title 'Users must be prevented from changing installation options.'
  desc '
Installation options for applications are typically controlled by administrators.  This setting prevents users from changing installation options that may bypass security features.
'
  tag 'stig','WN12-CC-000115'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000115_chk'
  tag fixid: 'F-WN12-CC-000115_fix'
  tag version: 'WN12-CC-000115'
  tag ruleid: 'WN12-CC-000115_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Allow user control over installs" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000115
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000115

end
