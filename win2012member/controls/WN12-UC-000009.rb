# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000009 - Zone information must be preserved when saving attachments.'

control 'WN12-UC-000009' do
  impact 0.5
  title 'Zone information must be preserved when saving attachments.'
  desc '
Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.
'
  tag 'stig','WN12-UC-000009'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UC-000009_chk'
  tag fixid: 'F-WN12-UC-000009_fix'
  tag version: 'WN12-UC-000009'
  tag ruleid: 'WN12-UC-000009_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Do not preserve zone information in file attachments" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: SaveZoneInformation

Type: REG_DWORD
Value: 2
'

# START_DESCRIBE WN12-UC-000009
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000009

end
