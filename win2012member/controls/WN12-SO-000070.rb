# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000070 - The system must be configured to meet the minimum session security requirement for NTLM SSP-based servers.'

control 'WN12-SO-000070' do
  impact 0.5
  title 'The system must be configured to meet the minimum session security requirement for NTLM SSP-based servers.'
  desc '
Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the options must be enabled to ensure the maximum security level.
'
  tag 'stig','WN12-SO-000070'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000070_chk'
  tag fixid: 'F-WN12-SO-000070_fix'
  tag version: 'WN12-SO-000070'
  tag ruleid: 'WN12-SO-000070_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\MSV1_0\

Value Name: NTLMMinServerSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)
'

# START_DESCRIBE WN12-SO-000070
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000070

end
