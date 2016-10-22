# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000073 - The shutdown option must not be available from the logon dialog box.'

control 'WN12-SO-000073' do
  impact 0.1
  title 'The shutdown option must not be available from the logon dialog box.'
  desc '
Displaying the shutdown button may allow individuals to shut down a system anonymously.  Only authenticated users should be allowed to shut down the system.  Preventing display of this button in the logon dialog box ensures that individuals who shut down the system are authorized and tracked in the system\'s Security event log.
'
  tag 'stig','WN12-SO-000073'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000073_chk'
  tag fixid: 'F-WN12-SO-000073_fix'
  tag version: 'WN12-SO-000073'
  tag ruleid: 'WN12-SO-000073_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Shutdown: Allow system to be shutdown without having to log on" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ShutdownWithoutLogon

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000073
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000073

end
