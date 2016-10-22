# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000028 - Group Policy objects must be reprocessed even if they have not changed.'

control 'WN12-CC-000028' do
  impact 0.5
  title 'Group Policy objects must be reprocessed even if they have not changed.'
  desc '
Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed.  This way, any unauthorized changes are forced to match the domain-based group policy settings again.
'
  tag 'stig','WN12-CC-000028'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000028_chk'
  tag fixid: 'F-WN12-CC-000028_fix'
  tag version: 'WN12-CC-000028'
  tag ruleid: 'WN12-CC-000028_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

Value Name: NoGPOListChanges

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000028
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000028

end
