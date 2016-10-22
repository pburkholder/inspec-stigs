# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000033 - Event Viewer Events.asp links must be turned off.'

control 'WN12-CC-000033' do
  impact 0.1
  title 'Event Viewer Events.asp links must be turned off.'
  desc '
Viewing events is a function of administrators, who must not access the Internet with privileged accounts.  This setting will disable  Events.asp hyperlinks in Event Viewer to prevent links to the Internet from within events.
'
  tag 'stig','WN12-CC-000033'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000033_chk'
  tag fixid: 'F-WN12-CC-000033_fix'
  tag version: 'WN12-CC-000033'
  tag ruleid: 'WN12-CC-000033_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Event Viewer "Events.asp" links" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\EventViewer\

Value Name: MicrosoftEventVwrDisableLinks

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000033
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000033

end
