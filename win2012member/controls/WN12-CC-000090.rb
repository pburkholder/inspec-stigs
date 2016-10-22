# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000090 - Turning off File Explorer heap termination on corruption must be disabled.'

control 'WN12-CC-000090' do
  impact 0.1
  title 'Turning off File Explorer heap termination on corruption must be disabled.'
  desc '
Legacy plug-in applications may continue to function when a File Explorer session has become corrupt.  Disabling this feature will prevent this.
'
  tag 'stig','WN12-CC-000090'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000090_chk'
  tag fixid: 'F-WN12-CC-000090_fix'
  tag version: 'WN12-CC-000090'
  tag ruleid: 'WN12-CC-000090_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off heap termination on corruption" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoHeapTerminationOnCorruption

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000090
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000090

end
