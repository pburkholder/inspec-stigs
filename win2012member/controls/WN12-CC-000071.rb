# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000071 - The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'

control 'WN12-CC-000071' do
  impact 0.1
  title 'The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.
'
  tag 'stig','WN12-CC-000071'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000071_chk'
  tag fixid: 'F-WN12-CC-000071_fix'
  tag version: 'WN12-CC-000071'
  tag ruleid: 'WN12-CC-000071_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Application Compatibility -> "Turn off Inventory Collector" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\AppCompat\

Value Name: DisableInventory

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000071
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000071

end
