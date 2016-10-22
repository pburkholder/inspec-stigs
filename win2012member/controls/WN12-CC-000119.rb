# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000119 - Users must be notified if the logon server was inaccessible and cached credentials were used.'

control 'WN12-CC-000119' do
  impact 0.1
  title 'Users must be notified if the logon server was inaccessible and cached credentials were used.'
  desc '
Notifying a user whether cached credentials were used may make them aware of connection issues.
'
  tag 'stig','WN12-CC-000119'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000119_chk'
  tag fixid: 'F-WN12-CC-000119_fix'
  tag version: 'WN12-CC-000119'
  tag ruleid: 'WN12-CC-000119_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options -> "Report when logon server was not available during user logon" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ReportControllerMissing

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000119
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000119

end
