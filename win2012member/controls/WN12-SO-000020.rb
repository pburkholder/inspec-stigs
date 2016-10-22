# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000020 - The machine account lockout threshold must be set to 10 on systems with BitLocker enabled.'

control 'WN12-SO-000020' do
  impact 0.5
  title 'The machine account lockout threshold must be set to 10 on systems with BitLocker enabled.'
  desc '
The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts should be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.
'
  tag 'stig','WN12-SO-000020'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000020_chk'
  tag fixid: 'F-WN12-SO-000020_fix'
  tag version: 'WN12-SO-000020'
  tag ruleid: 'WN12-SO-000020_rule'
  tag fixtext: '
If BitLocker is enabled for the OS volumes, configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Machine account lockout threshold" to "10" invalid logon attempts.
'
  tag checktext: '
Verify whether BitLocker is enabled for the OS volumes in "BitLocker Drive Encryption" in Control Panel.  If BitLocker is not enabled, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: MaxDevicePasswordFailedAttempts

Value Type: REG_DWORD
Value: 0x0000000a (10)
'

# START_DESCRIBE WN12-SO-000020
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000020

end
