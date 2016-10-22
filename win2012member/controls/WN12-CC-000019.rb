# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000019 - Remote access to the Plug and Play interface must be disabled for device installation.'

control 'WN12-CC-000019' do
  impact 0.5
  title 'Remote access to the Plug and Play interface must be disabled for device installation.'
  desc '
Remote access to the Plug and Play interface could potentially allow connections by unauthorized devices.  This setting configures remote access to the Plug and Play interface and must be disabled.
'
  tag 'stig','WN12-CC-000019'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000019_chk'
  tag fixid: 'F-WN12-CC-000019_fix'
  tag version: 'WN12-CC-000019'
  tag ruleid: 'WN12-CC-000019_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Allow remote access to the Plug and Play interface" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DeviceInstall\Settings\

Value Name: AllowRemoteRPC

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000019
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000019

end
