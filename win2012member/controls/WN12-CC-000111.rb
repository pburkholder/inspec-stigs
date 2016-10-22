# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000111 - Microsoft Active Protection Service membership must be disabled.'

control 'WN12-CC-000111' do
  impact 0.5
  title 'Microsoft Active Protection Service membership must be disabled.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting disables Microsoft Active Protection Service membership and reporting.
'
  tag 'stig','WN12-CC-000111'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000111_chk'
  tag fixid: 'F-WN12-CC-000111_fix'
  tag version: 'WN12-CC-000111'
  tag ruleid: 'WN12-CC-000111_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender -> "Configure Microsoft Active Protection Service Reporting " to "Disabled".
'
  tag checktext: '
If the following registry value exists and is set to "1" (Basic) or "2" (Advanced), this is a finding:

If the registry value does not exist, this is not a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows Defender\Spynet\

Value Name: SpyNetReporting

Type: REG_DWORD
Value: 1 or 2 = a Finding
'

# START_DESCRIBE WN12-CC-000111
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000111

end
