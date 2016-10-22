# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000012 - Outgoing secure channel traffic must be encrypted or signed.'

control 'WN12-SO-000012' do
  impact 0.5
  title 'Outgoing secure channel traffic must be encrypted or signed.'
  desc '
Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.
'
  tag 'stig','WN12-SO-000012'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000012_chk'
  tag fixid: 'F-WN12-SO-000012_fix'
  tag version: 'WN12-SO-000012'
  tag ruleid: 'WN12-SO-000012_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Digitally encrypt or sign secure channel data (always)" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000012
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000012

end
