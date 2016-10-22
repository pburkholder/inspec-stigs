# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000061 - Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'

control 'WN12-SO-000061' do
  impact 0.5
  title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'
  desc '
Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously vs. using the computer identity.
'
  tag 'stig','WN12-SO-000061'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000061_chk'
  tag fixid: 'F-WN12-SO-000061_fix'
  tag version: 'WN12-SO-000061'
  tag ruleid: 'WN12-SO-000061_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow Local System to use computer identity for NTLM" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Control\LSA\

Value Name: UseMachineId

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000061
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000061

end
