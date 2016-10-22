# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000086 - The Setup event log must be configured to a minimum size requirement.'

control 'WN12-CC-000086' do
  impact 0.5
  title 'The Setup event log must be configured to a minimum size requirement.'
  desc '
Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel.
'
  tag 'stig','WN12-CC-000086'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000086_chk'
  tag fixid: 'F-WN12-CC-000086_fix'
  tag version: 'WN12-CC-000086'
  tag ruleid: 'WN12-CC-000086_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> Setup -> "Specify the maximum log size (KB)" to at minimum "Enabled:32768".
'
  tag checktext: '
If the following registry value does not exist or is not configured to at least the value specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: Software\Policies\Microsoft\Windows\EventLog\Setup

Value Name:  MaxSize

Type: REG_DWORD
Value: 32768

If the system is configured to write events directly to an audit server, this is NA.
'

# START_DESCRIBE WN12-CC-000086
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000086

end
