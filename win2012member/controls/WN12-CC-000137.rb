# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000137 - The system must be configured to remove the Disconnect option from the Shut Down dialog box on the Remote Desktop Client.  (Remote Desktop Services Role).'

control 'WN12-CC-000137' do
  impact 0.1
  title 'The system must be configured to remove the Disconnect option from the Shut Down dialog box on the Remote Desktop Client.  (Remote Desktop Services Role).'
  desc '
Removing the Disconnect option from the Shut Down dialog box for Remote Desktop sessions helps prevent disconnected but active sessions from continuing to run and using resources.
'
  tag 'stig','WN12-CC-000137'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000137_chk'
  tag fixid: 'F-WN12-CC-000137_fix'
  tag version: 'WN12-CC-000137'
  tag ruleid: 'WN12-CC-000137_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Remote Session Environment "Remove "Disconnect" option from Shut Down dialog" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer

Value Name: NoDisconnect

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000137
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000137

end
