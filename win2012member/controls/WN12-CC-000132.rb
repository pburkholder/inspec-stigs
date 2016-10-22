# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000132 - Users must be prevented from mapping local COM ports and redirecting data from the Remote Desktop Session Host to local COM ports.  (Remote Desktop Services Role).'

control 'WN12-CC-000132' do
  impact 0.5
  title 'Users must be prevented from mapping local COM ports and redirecting data from the Remote Desktop Session Host to local COM ports.  (Remote Desktop Services Role).'
  desc '
Preventing the redirection of Remote Desktop session data to a client computer\'s COM ports helps reduce possible exposure of sensitive data.
'
  tag 'stig','WN12-CC-000132'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000132_chk'
  tag fixid: 'F-WN12-CC-000132_fix'
  tag version: 'WN12-CC-000132'
  tag ruleid: 'WN12-CC-000132_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection "Do not allow COM port redirection" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fDisableCcm

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000132
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000132

end
