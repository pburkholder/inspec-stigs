# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000062 - Remote Assistance log files must be generated.'

control 'WN12-CC-000062' do
  impact 0.1
  title 'Remote Assistance log files must be generated.'
  desc '
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting will turn on session logging for Remote Assistance connections.
'
  tag 'stig','WN12-CC-000062'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000062_chk'
  tag fixid: 'F-WN12-CC-000062_fix'
  tag version: 'WN12-CC-000062'
  tag ruleid: 'WN12-CC-000062_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Turn on session logging" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: LoggingEnabled

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000062
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000062

end
