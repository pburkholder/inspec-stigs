# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000065 - The system must be configured to prevent the storage of the LAN Manager hash of passwords.'

control 'WN12-SO-000065' do
  impact 1.0
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc '
The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords.  This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.
'
  tag 'stig','WN12-SO-000065'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000065_chk'
  tag fixid: 'F-WN12-SO-000065_fix'
  tag version: 'WN12-SO-000065'
  tag ruleid: 'WN12-SO-000065_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000065
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000065

end
