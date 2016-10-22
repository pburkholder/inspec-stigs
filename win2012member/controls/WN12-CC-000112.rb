# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000112 - Error Reporting events must be logged in the system event log.'

control 'WN12-CC-000112' do
  impact 0.1
  title 'Error Reporting events must be logged in the system event log.'
  desc '
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting ensures that Error Reporting events will be logged in the system event log.
'
  tag 'stig','WN12-CC-000112'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000112_chk'
  tag fixid: 'F-WN12-CC-000112_fix'
  tag version: 'WN12-CC-000112'
  tag ruleid: 'WN12-CC-000112_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Disable Logging" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name: LoggingDisabled

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000112
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000112

end
