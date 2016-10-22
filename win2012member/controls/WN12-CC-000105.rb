# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000105 - Attachments must be prevented from being downloaded from RSS feeds.'

control 'WN12-CC-000105' do
  impact 0.5
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc '
Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.
'
  tag 'stig','WN12-CC-000105'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000105_chk'
  tag fixid: 'F-WN12-CC-000105_fix'
  tag version: 'WN12-CC-000105'
  tag ruleid: 'WN12-CC-000105_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Prevent downloading of enclosures" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000105
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000105

end
