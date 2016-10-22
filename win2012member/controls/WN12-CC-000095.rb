# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000095 - The location feature must be turned off.'

control 'WN12-CC-000095' do
  impact 0.5
  title 'The location feature must be turned off.'
  desc '
The location service on systems may allow sensitive data to be used by applications on the system.  This should be turned off unless explicitly allowed for approved systems/applications.
'
  tag 'stig','WN12-CC-000095'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000095_chk'
  tag fixid: 'F-WN12-CC-000095_fix'
  tag version: 'WN12-CC-000095'
  tag ruleid: 'WN12-CC-000095_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Location and Sensors -> "Turn off location" to "Enabled".

If location services are approved by the organization for a device, this must be documented.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\LocationAndSensors\

Value Name: DisableLocation

Type: REG_DWORD
Value: 1 (Enabled)

If location services are approved for the system by the organization, this may be set to "Disabled" (0).  This must be documented with the IAO.
'

# START_DESCRIBE WN12-CC-000095
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000095

end
