# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000021 - The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'

control 'WN12-SO-000021' do
  impact 0.5
  title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
  desc '
Unattended systems are susceptible to unauthorized use and should be locked when unattended.  The screen saver should be set at a maximum of 15 minutes and be password protected.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.
'
  tag 'stig','WN12-SO-000021'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000021_chk'
  tag fixid: 'F-WN12-SO-000021_fix'
  tag version: 'WN12-SO-000021'
  tag ruleid: 'WN12-SO-000021_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Machine inactivity limit" to "900" seconds" or less.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900) (or less)
'

# START_DESCRIBE WN12-SO-000021
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000021

end
