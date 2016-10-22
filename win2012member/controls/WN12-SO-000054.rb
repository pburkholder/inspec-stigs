# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000054 - The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'

control 'WN12-SO-000054' do
  impact 0.5
  title 'The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'
  desc '
Access by anonymous users must be restricted.  If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users must not have these permissions or rights.
'
  tag 'stig','WN12-SO-000054'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000054_chk'
  tag fixid: 'F-WN12-SO-000054_fix'
  tag version: 'WN12-SO-000054'
  tag ruleid: 'WN12-SO-000054_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Let everyone permissions apply to anonymous users" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-SO-000054
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000054

end
