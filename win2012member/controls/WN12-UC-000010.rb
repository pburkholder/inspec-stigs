# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000010 - Mechanisms for removing zone information from file attachments must be hidden.'

control 'WN12-UC-000010' do
  impact 0.5
  title 'Mechanisms for removing zone information from file attachments must be hidden.'
  desc '
Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.  This setting prevents users from manually removing zone information from saved file attachments.
'
  tag 'stig','WN12-UC-000010'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UC-000010_chk'
  tag fixid: 'F-WN12-UC-000010_fix'
  tag version: 'WN12-UC-000010'
  tag ruleid: 'WN12-UC-000010_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Hide mechanisms to remove zone information" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: HideZoneInfoOnProperties

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-UC-000010
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000010

end
