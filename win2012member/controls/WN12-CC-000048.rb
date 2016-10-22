# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000048 - Copying of user input methods to the system account for sign-in must be prevented.'

control 'WN12-CC-000048' do
  impact 0.5
  title 'Copying of user input methods to the system account for sign-in must be prevented.'
  desc '
Allowing different input methods for sign-in could open different avenues of attack.  User input methods must be restricted to those enabled for the system account at sign-in.
'
  tag 'stig','WN12-CC-000048'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000048_chk'
  tag fixid: 'F-WN12-CC-000048_fix'
  tag version: 'WN12-CC-000048'
  tag ruleid: 'WN12-CC-000048_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Locale Services -> "Disallow copying of user input methods to the system account for sign-in" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Control Panel\International\

Value Name: BlockUserInputMethodsForSignIn

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000048
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000048

end
