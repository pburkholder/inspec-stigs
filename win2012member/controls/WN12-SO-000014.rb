# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000014 - Outgoing secure channel traffic must be signed when possible.'

control 'WN12-SO-000014' do
  impact 0.5
  title 'Outgoing secure channel traffic must be signed when possible.'
  desc '
Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked.  If this policy is enabled, outgoing secure channel traffic will be signed.
'
  tag 'stig','WN12-SO-000014'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000014_chk'
  tag fixid: 'F-WN12-SO-000014_fix'
  tag version: 'WN12-SO-000014'
  tag ruleid: 'WN12-SO-000014_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Digitally sign secure channel data (when possible)" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: SignSecureChannel

Value Type: REG_DWORD
Value: 1

If the value for "Domain Member: Digitally encrypt or sign secure channel data (always)" is set to "Enabled", this can be NA (see V-6831).
'

# START_DESCRIBE WN12-SO-000014
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000014

end
