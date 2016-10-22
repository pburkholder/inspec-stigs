# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000062 - NTLM must be prevented from falling back to a Null session.'

control 'WN12-SO-000062' do
  impact 0.5
  title 'NTLM must be prevented from falling back to a Null session.'
  desc '
NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.
'
  tag 'stig','WN12-SO-000062'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000062_chk'
  tag fixid: 'F-WN12-SO-000062_fix'
  tag version: 'WN12-SO-000062'
  tag ruleid: 'WN12-SO-000062_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow LocalSystem NULL session fallback" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Control\LSA\MSV1_0\

Value Name: allownullsessionfallback

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000062
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000062

end
