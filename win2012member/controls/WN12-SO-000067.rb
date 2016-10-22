# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000067 - The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.'

control 'WN12-SO-000067' do
  impact 1.0
  title 'The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.'
  desc '
The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts.  NTLM, which is less secure, is retained in later Windows versions  for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it.  It is also used to authenticate logons to stand-alone computers that are running later versions.
'
  tag 'stig','WN12-SO-000067'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000067_chk'
  tag fixid: 'F-WN12-SO-000067_fix'
  tag version: 'WN12-SO-000067'
  tag ruleid: 'WN12-SO-000067_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: LmCompatibilityLevel

Value Type: REG_DWORD
Value: 5
'

# START_DESCRIBE WN12-SO-000067
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000067

end
