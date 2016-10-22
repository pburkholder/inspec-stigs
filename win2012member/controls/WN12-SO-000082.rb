# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000082 - User Account Control must only elevate UIAccess applications that are installed in secure locations.'

control 'WN12-SO-000082' do
  impact 0.5
  title 'User Account Control must only elevate UIAccess applications that are installed in secure locations.'
  desc '
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\System32 folders, to run with elevated privileges.
'
  tag 'stig','WN12-SO-000082'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000082_chk'
  tag fixid: 'F-WN12-SO-000082_fix'
  tag version: 'WN12-SO-000082'
  tag ruleid: 'WN12-SO-000082_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled".

UAC requirements are NA on Server Core installations.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableSecureUIAPaths

Value Type: REG_DWORD
Value: 1

UAC requirements are NA on Server Core installations.
'

# START_DESCRIBE WN12-SO-000082
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000082

end
