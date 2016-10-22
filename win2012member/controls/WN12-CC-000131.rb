# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000131 - Remote Desktop Services must limit users to one remote session.'

control 'WN12-CC-000131' do
  impact 0.5
  title 'Remote Desktop Services must limit users to one remote session.'
  desc '
Allowing multiple Remote Desktop Services sessions could consume resources.  There is also potential to make a secondary connection to a system with compromised credentials.
'
  tag 'stig','WN12-CC-000131'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000131_chk'
  tag fixid: 'F-WN12-CC-000131_fix'
  tag version: 'WN12-CC-000131'
  tag ruleid: 'WN12-CC-000131_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Connections "Restrict Remote Desktop Services users to a single Remote Desktop Services Session" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\ 

Value Name: fSingleSessionPerUser 

Type: REG_DWORD 
Value: 1
'

# START_DESCRIBE WN12-CC-000131
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000131

end
