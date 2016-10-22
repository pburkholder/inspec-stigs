# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000012 - Users must be prevented from sharing files in their profiles.'

control 'WN12-UC-000012' do
  impact 0.5
  title 'Users must be prevented from sharing files in their profiles.'
  desc '
Allowing users to share files in their profiles may provide unauthorized access or result in the exposure of sensitive data.
'
  tag 'stig','WN12-UC-000012'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UC-000012_chk'
  tag fixid: 'F-WN12-UC-000012_fix'
  tag version: 'WN12-UC-000012'
  tag ruleid: 'WN12-UC-000012_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Network Sharing -> "Prevent users from sharing files within their profile" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoInPlaceSharing

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-UC-000012
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000012

end
