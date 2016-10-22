# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000018 - Optional component installation and component repair must be prevented from using Windows Update.'

control 'WN12-CC-000018' do
  impact 0.1
  title 'Optional component installation and component repair must be prevented from using Windows Update.'
  desc '
Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Optional component installation or repair must be obtained from an internal source.
'
  tag 'stig','WN12-CC-000018'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000018_chk'
  tag fixid: 'F-WN12-CC-000018_fix'
  tag version: 'WN12-CC-000018'
  tag ruleid: 'WN12-CC-000018_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> "Specify settings for optional component installation and component repair" to "Enabled" and with "Never attempt to download payload from Windows Update" selected.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Servicing \

Value Name: UseWindowsUpdate

Type: REG_DWORD
Value: 2
'

# START_DESCRIBE WN12-CC-000018
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000018

end
