# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000002 - A screen saver must be defined.'

control 'WN12-UC-000002' do
  impact 0.1
  title 'A screen saver must be defined.'
  desc '
Unattended systems are susceptible to unauthorized use and must be locked.  Specifying a screen saver ensures the screen saver timeout lock is initiated properly.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.
'
  tag 'stig','WN12-UC-000002'
  tag severity: 'low'
  tag checkid: 'C-WN12-UC-000002_chk'
  tag fixid: 'F-WN12-UC-000002_fix'
  tag version: 'WN12-UC-000002'
  tag ruleid: 'WN12-UC-000002_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Force specific screen saver" to "Enabled" with "scrnsave.scr" specified as the screen saver executable name.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Windows\Control Panel\Desktop\

Value Name: SCRNSAVE.EXE

Type: REG_SZ
Value: scrnsave.scr
'

# START_DESCRIBE WN12-UC-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000002

end
