# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000046 - The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.'

control 'WN12-SO-000046' do
  impact 0.1
  title 'The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.'
  desc '
Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log on to the system before the lock takes effect.
'
  tag 'stig','WN12-SO-000046'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000046_chk'
  tag fixid: 'F-WN12-SO-000046_fix'
  tag version: 'WN12-SO-000046'
  tag ruleid: 'WN12-SO-000046_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" to "5" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: ScreenSaverGracePeriod

Value Type: REG_SZ
Value: 5 (or less)
'

# START_DESCRIBE WN12-SO-000046
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000046

end
