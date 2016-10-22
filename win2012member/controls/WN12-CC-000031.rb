# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000031 - Root Certificates must not be updated automatically from the Microsoft site.'

control 'WN12-CC-000031' do
  impact 0.1
  title 'Root Certificates must not be updated automatically from the Microsoft site.'
  desc '
Root Certificate updates must be controlled in the enterprise to ensure a proper validation chain is maintained.  This setting prevents root certificates from being updated automatically from the Microsoft site.
'
  tag 'stig','WN12-CC-000031'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000031_chk'
  tag fixid: 'F-WN12-CC-000031_fix'
  tag version: 'WN12-CC-000031'
  tag ruleid: 'WN12-CC-000031_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Automatic Root Certificates Update" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\SystemCertificates\AuthRoot\

Value Name: DisableRootAutoUpdate

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000031
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000031

end
