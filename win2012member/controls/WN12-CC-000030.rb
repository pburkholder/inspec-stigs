# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000030 - Access to the Windows Store must be turned off.'

control 'WN12-CC-000030' do
  impact 0.5
  title 'Access to the Windows Store must be turned off.'
  desc '
Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  Turning off access to the Windows Store will limit access to publicly available applications.
'
  tag 'stig','WN12-CC-000030'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000030_chk'
  tag fixid: 'F-WN12-CC-000030_fix'
  tag version: 'WN12-CC-000030'
  tag ruleid: 'WN12-CC-000030_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off access to the Store" to "Enabled".

The Windows Store is not installed by default.  If the \Windows\WindowsStore directory does not exist, this is NA.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoUseStoreOpenWith

Type: REG_DWORD
Value: 1

The Windows Store is not installed by default.  If the \Windows\WindowsStore directory does not exist, this is NA.
'

# START_DESCRIBE WN12-CC-000030
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000030

end
