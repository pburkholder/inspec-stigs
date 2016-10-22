# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000100 - Remote Desktop Services must be configured with the client connection encryption set to the required level.'

control 'WN12-CC-000100' do
  impact 0.5
  title 'Remote Desktop Services must be configured with the client connection encryption set to the required level.'
  desc '
Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.
'
  tag 'stig','WN12-CC-000100'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000100_chk'
  tag fixid: 'F-WN12-CC-000100_fix'
  tag version: 'WN12-CC-000100'
  tag ruleid: 'WN12-CC-000100_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Set client connection encryption level" to "Enabled" and "High Level".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 3
'

# START_DESCRIBE WN12-CC-000100
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000100

end
