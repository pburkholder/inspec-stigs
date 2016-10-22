# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000130 - The Remote Desktop Session Host must require secure RPC communications.'

control 'WN12-CC-000130' do
  impact 0.5
  title 'The Remote Desktop Session Host must require secure RPC communications.'
  desc '
Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks.  A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged.  Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.
'
  tag 'stig','WN12-CC-000130'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000130_chk'
  tag fixid: 'F-WN12-CC-000130_fix'
  tag version: 'WN12-CC-000130'
  tag ruleid: 'WN12-CC-000130_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security "Require secure RPC communication" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fEncryptRPCTraffic

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000130
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000130

end
