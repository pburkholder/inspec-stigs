# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000087 - The System event log must be configured to a minimum size requirement.'

control 'WN12-CC-000087' do
  impact 0.5
  title 'The System event log must be configured to a minimum size requirement.'
  desc '
Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel.
'
  tag 'stig','WN12-CC-000087'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000087_chk'
  tag fixid: 'F-WN12-CC-000087_fix'
  tag version: 'WN12-CC-000087'
  tag ruleid: 'WN12-CC-000087_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> System -> "Specify the maximum log size (KB)" to at minimum "Enabled:32768".
'
  tag checktext: '
If the following registry value does not exist or is not configured to at least the value specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: Software\Policies\Microsoft\Windows\EventLog\System

Value Name:  MaxSize

Type: REG_DWORD
Value: 32768

If the system is configured to write events directly to an audit server, this is NA.
'

# START_DESCRIBE WN12-CC-000087
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000087

end
