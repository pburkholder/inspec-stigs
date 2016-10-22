# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000084 - User Account Control must switch to the secure desktop when prompting for elevation.'

control 'WN12-SO-000084' do
  impact 0.5
  title 'User Account Control must switch to the secure desktop when prompting for elevation.'
  desc '
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting ensures that the elevation prompt is only used in secure desktop mode.
'
  tag 'stig','WN12-SO-000084'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000084_chk'
  tag fixid: 'F-WN12-SO-000084_fix'
  tag version: 'WN12-SO-000084'
  tag ruleid: 'WN12-SO-000084_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Switch to the secure desktop when prompting for elevation" to "Enabled".

UAC requirements are NA on Server Core installations.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: PromptOnSecureDesktop

Value Type: REG_DWORD
Value: 1

UAC requirements are NA on Server Core installations.
'

# START_DESCRIBE WN12-SO-000084
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000084

end
