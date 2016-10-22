# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000073 - The default autorun behavior must be configured to prevent autorun commands.'

control 'WN12-CC-000073' do
  impact 1.0
  title 'The default autorun behavior must be configured to prevent autorun commands.'
  desc '
Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.
'
  tag 'stig','WN12-CC-000073'
  tag severity: 'high'
  tag checkid: 'C-WN12-CC-000073_chk'
  tag fixid: 'F-WN12-CC-000073_fix'
  tag version: 'WN12-CC-000073'
  tag ruleid: 'WN12-CC-000073_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoAutorun

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000073
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000073

end
