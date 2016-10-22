# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000025 - Users must be warned in advance of their passwords expiring.'

control 'WN12-SO-000025' do
  impact 0.1
  title 'Users must be warned in advance of their passwords expiring.'
  desc '
Creating strong passwords that can be remembered by users requires some thought.  By giving the user advance warning, the user has time to construct a sufficiently strong password.  This setting configures the system to display a warning to users telling them how many days are left before their password expires.
'
  tag 'stig','WN12-SO-000025'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000025_chk'
  tag fixid: 'F-WN12-SO-000025_fix'
  tag version: 'WN12-SO-000025'
  tag ruleid: 'WN12-SO-000025_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Prompt user to change password before expiration" to "14" days or more.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: PasswordExpiryWarning

Value Type: REG_DWORD
Value: 14 (or greater)
'

# START_DESCRIBE WN12-SO-000025
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000025

end
