# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000109 - Automatic download of updates from the Windows Store must be turned off.'

control 'WN12-CC-000109' do
  impact 0.1
  title 'Automatic download of updates from the Windows Store must be turned off.'
  desc '
Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially allow sensitive information outside of the enterprise.  Application updates must be obtained from an internal source.
'
  tag 'stig','WN12-CC-000109'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000109_chk'
  tag fixid: 'F-WN12-CC-000109_fix'
  tag version: 'WN12-CC-000109'
  tag ruleid: 'WN12-CC-000109_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> "Turn off Automatic Download of updates" to "Enabled".

The Windows Store is not installed by default.  If the \Windows\WindowsStore directory does not exist, this is NA.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsStore\WindowsUpdate\

Value Name: AutoDownload

Type: REG_DWORD
Value: 2

The Windows Store is not installed by default.  If the \Windows\WindowsStore directory does not exist, this is NA.
'

# START_DESCRIBE WN12-CC-000109
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000109

end
