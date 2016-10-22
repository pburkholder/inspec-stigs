# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000059 - Solicited Remote Assistance must not be allowed.'

control 'WN12-CC-000059' do
  impact 1.0
  title 'Solicited Remote Assistance must not be allowed.'
  desc '
Remote assistance allows another user to view or take control of the local session of a user.  Solicited assistance is help that is specifically requested by the local user.  This may allow unauthorized parties access to the resources on the computer.
'
  tag 'stig','WN12-CC-000059'
  tag severity: 'high'
  tag checkid: 'C-WN12-CC-000059_chk'
  tag fixid: 'F-WN12-CC-000059_fix'
  tag version: 'WN12-CC-000059'
  tag ruleid: 'WN12-CC-000059_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Solicited Remote Assistance" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\ 

Value Name: fAllowToGetHelp
 
Type: REG_DWORD 
Value: 0
'

# START_DESCRIBE WN12-CC-000059
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000059

end
