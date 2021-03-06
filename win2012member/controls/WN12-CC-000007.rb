# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000007 - The 6to4 IPv6 transition technology must be disabled.'

control 'WN12-CC-000007' do
  impact 0.5
  title 'The 6to4 IPv6 transition technology must be disabled.'
  desc '
IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.
'
  tag 'stig','WN12-CC-000007'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000007_chk'
  tag fixid: 'F-WN12-CC-000007_fix'
  tag version: 'WN12-CC-000007'
  tag ruleid: 'WN12-CC-000007_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set 6to4 State" to "Enabled: Disabled State".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\TCPIP\v6Transition\

Value Name: 6to4_State

Type: REG_SZ
Value: Disabled
'

# START_DESCRIBE WN12-CC-000007
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000007

end
