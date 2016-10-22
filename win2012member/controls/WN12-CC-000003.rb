# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000003 - Windows Peer-to-Peer Networking Services must be turned off.'

control 'WN12-CC-000003' do
  impact 0.5
  title 'Windows Peer-to-Peer Networking Services must be turned off.'
  desc '
Peer-to-Peer applications can allow unauthorized access to a system and exposure of sensitive data.  This setting will turn off the Microsoft Peer-to-Peer Networking Service.
'
  tag 'stig','WN12-CC-000003'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000003_chk'
  tag fixid: 'F-WN12-CC-000003_fix'
  tag version: 'WN12-CC-000003'
  tag ruleid: 'WN12-CC-000003_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services -> "Turn off Microsoft Peer-to-Peer Networking Services" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Peernet\

Value Name: Disabled

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000003

end
