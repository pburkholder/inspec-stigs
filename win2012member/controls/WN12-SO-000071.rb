# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000071 - The Recovery Console option must be set to prevent automatic logon to the system.'

control 'WN12-SO-000071' do
  impact 1.0
  title 'The Recovery Console option must be set to prevent automatic logon to the system.'
  desc '
If this option is enabled, the Recovery Console does not require a password and automatically logs on to the system.  This could allow unauthorized administrative access to the system.
'
  tag 'stig','WN12-SO-000071'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000071_chk'
  tag fixid: 'F-WN12-SO-000071_fix'
  tag version: 'WN12-SO-000071'
  tag ruleid: 'WN12-SO-000071_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Recovery console: Allow automatic administrative logon" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\

Value Name: SecurityLevel

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000071
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000071

end
