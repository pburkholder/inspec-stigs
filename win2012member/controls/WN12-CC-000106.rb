# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000106 - Basic authentication for RSS feeds over HTTP must be turned off.'

control 'WN12-CC-000106' do
  impact 0.5
  title 'Basic authentication for RSS feeds over HTTP must be turned off.'
  desc '
Basic authentication uses plain text passwords that could be used to compromise a system.
'
  tag 'stig','WN12-CC-000106'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000106_chk'
  tag fixid: 'F-WN12-CC-000106_fix'
  tag version: 'WN12-CC-000106'
  tag ruleid: 'WN12-CC-000106_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Turn on Basic feed authentication over HTTP" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: AllowBasicAuthInClear

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000106
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000106

end
