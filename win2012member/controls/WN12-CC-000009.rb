# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000009 - The ISATAP IPv6 transition technology must be disabled.'

control 'WN12-CC-000009' do
  impact 0.5
  title 'The ISATAP IPv6 transition technology must be disabled.'
  desc '
IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.
'
  tag 'stig','WN12-CC-000009'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000009_chk'
  tag fixid: 'F-WN12-CC-000009_fix'
  tag version: 'WN12-CC-000009'
  tag ruleid: 'WN12-CC-000009_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set ISATAP State" to "Enabled: Disabled State".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\TCPIP\v6Transition\

Value Name: ISATAP_State

Type: REG_SZ
Value: Disabled
'

# START_DESCRIBE WN12-CC-000009
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000009

end
