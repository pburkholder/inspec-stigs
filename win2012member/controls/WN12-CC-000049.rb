# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000049 - The classic logon screen must be required for user logons.'

control 'WN12-CC-000049' do
  impact 0.1
  title 'The classic logon screen must be required for user logons.'
  desc '
The classic logon screen requires users to enter a logon name and password to access a system.  The simple logon screen or Welcome screen displays  usernames for selection, providing part of the necessary logon information.
'
  tag 'stig','WN12-CC-000049'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000049_chk'
  tag fixid: 'F-WN12-CC-000049_fix'
  tag version: 'WN12-CC-000049'
  tag ruleid: 'WN12-CC-000049_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Always use classic logon" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: LogonType

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000049
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000049

end
