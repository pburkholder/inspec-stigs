# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000059 - Network shares that can be accessed anonymously must not be allowed.'

control 'WN12-SO-000059' do
  impact 1.0
  title 'Network shares that can be accessed anonymously must not be allowed.'
  desc '
Anonymous access to network shares provides the potential for gaining unauthorized system access by network users.  This could lead to the exposure or corruption of sensitive data.
'
  tag 'stig','WN12-SO-000059'
  tag severity: 'high'
  tag checkid: 'C-WN12-SO-000059_chk'
  tag fixid: 'F-WN12-SO-000059_fix'
  tag version: 'WN12-SO-000059'
  tag ruleid: 'WN12-SO-000059_rule'
  tag fixtext: '
Ensure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Shares that can be accessed anonymously" contains no entries (blank).
'
  tag checktext: '
If the following registry value does not exist, this is not a finding:

If the following registry value does exist and is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: NullSessionShares

Value Type: REG_MULTI_SZ
Value: (Blank)
'

# START_DESCRIBE WN12-SO-000059
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000059

end
