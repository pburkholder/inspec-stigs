# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000060 - The system must be configured to use the Classic security model.'

control 'WN12-SO-000060' do
  impact 0.5
  title 'The system must be configured to use the Classic security model.'
  desc '
Windows includes two network-sharing security models - Classic and Guest only.  With the Classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources.
'
  tag 'stig','WN12-SO-000060'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000060_chk'
  tag fixid: 'F-WN12-SO-000060_fix'
  tag version: 'WN12-SO-000060'
  tag ruleid: 'WN12-SO-000060_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: ForceGuest

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000060
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000060

end
