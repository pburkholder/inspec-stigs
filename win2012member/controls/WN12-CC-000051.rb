# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000051 - Local users on domain-joined computers must not be enumerated.'

control 'WN12-CC-000051' do
  impact 0.5
  title 'Local users on domain-joined computers must not be enumerated.'
  desc '
The username is one part of logon credentials that could be used to gain access to a system.  Preventing the enumeration of users limits this information to authorized personnel.
'
  tag 'stig','WN12-CC-000051'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000051_chk'
  tag fixid: 'F-WN12-CC-000051_fix'
  tag version: 'WN12-CC-000051'
  tag ruleid: 'WN12-CC-000051_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Enumerate local users on domain-joined computers" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\System\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000051
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000051

end
