# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UC-000011 - The system must notify antivirus when file attachments are opened.'

control 'WN12-UC-000011' do
  impact 0.5
  title 'The system must notify antivirus when file attachments are opened.'
  desc '
Attaching malicious files is a known avenue of attack.  This setting configures the system to notify antivirus programs when a user opens a file attachment.
'
  tag 'stig','WN12-UC-000011'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UC-000011_chk'
  tag fixid: 'F-WN12-UC-000011_fix'
  tag version: 'WN12-UC-000011'
  tag ruleid: 'WN12-UC-000011_rule'
  tag fixtext: '
Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Notify antivirus programs when opening attachments" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: ScanWithAntiVirus

Type: REG_DWORD
Value: 3
'

# START_DESCRIBE WN12-UC-000011
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UC-000011

end
