# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000077 - User Account Control approval mode for the built-in Administrator must be enabled.'

control 'WN12-SO-000077' do
  impact 0.5
  title 'User Account Control approval mode for the built-in Administrator must be enabled.'
  desc '
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.
'
  tag 'stig','WN12-SO-000077'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000077_chk'
  tag fixid: 'F-WN12-SO-000077_fix'
  tag version: 'WN12-SO-000077'
  tag ruleid: 'WN12-SO-000077_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled".

UAC requirements are NA on Server Core installations.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 1

UAC requirements are NA on Server Core installations.
'

# START_DESCRIBE WN12-SO-000077
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000077

end
