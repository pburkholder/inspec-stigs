# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000018 - The system must be configured to prevent the display of the last username on the logon screen.'

control 'WN12-SO-000018' do
  impact 0.1
  title 'The system must be configured to prevent the display of the last username on the logon screen.'
  desc '
Displaying the username of the last logged on user provides half of the userid/password equation that an unauthorized person would need to gain access.  The username of the last user to log on to a system must not be displayed.
'
  tag 'stig','WN12-SO-000018'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000018_chk'
  tag fixid: 'F-WN12-SO-000018_fix'
  tag version: 'WN12-SO-000018'
  tag ruleid: 'WN12-SO-000018_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Do not display last user name" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DontDisplayLastUserName

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000018
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000018

end
