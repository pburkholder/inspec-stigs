# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000098 - Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).'

control 'WN12-CC-000098' do
  impact 0.5
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).'
  desc '
Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.
'
  tag 'stig','WN12-CC-000098'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000098_chk'
  tag fixid: 'F-WN12-CC-000098_fix'
  tag version: 'WN12-CC-000098'
  tag ruleid: 'WN12-CC-000098_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow drive redirection" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fDisableCdm

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000098
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000098

end
