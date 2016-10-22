# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000025 - Device driver updates must only search managed servers, not Windows Update.'

control 'WN12-CC-000025' do
  impact 0.1
  title 'Device driver updates must only search managed servers, not Windows Update.'
  desc '
Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Device driver updates must be obtained from an internal source.
'
  tag 'stig','WN12-CC-000025'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000025_chk'
  tag fixid: 'F-WN12-CC-000025_fix'
  tag version: 'WN12-CC-000025'
  tag ruleid: 'WN12-CC-000025_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify the search server for device driver updates" to "Enabled" with "Search Managed Server" selected.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: DriverServerSelection

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000025
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000025

end
