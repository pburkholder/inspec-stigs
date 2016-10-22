# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000078 - User Account Control must, at minimum, prompt administrators for consent.'

control 'WN12-SO-000078' do
  impact 0.5
  title 'User Account Control must, at minimum, prompt administrators for consent.'
  desc '
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.
'
  tag 'stig','WN12-SO-000078'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000078_chk'
  tag fixid: 'F-WN12-SO-000078_fix'
  tag version: 'WN12-SO-000078'
  tag ruleid: 'WN12-SO-000078_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".

More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop).

UAC requirements are NA on Server Core installations.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 4 (Prompt for consent)
3 (Prompt for credentials)
2 (Prompt for consent on the secure desktop)
1 (Prompt for credentials on the secure desktop)

UAC requirements are NA on Server Core installations.
'

# START_DESCRIBE WN12-SO-000078
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000078

end
