# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000114 - Additional data requests in response to Error Reporting must be declined.'

control 'WN12-CC-000114' do
  impact 0.1
  title 'Additional data requests in response to Error Reporting must be declined.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents additional data requests in response to Error Reporting.
'
  tag 'stig','WN12-CC-000114'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000114_chk'
  tag fixid: 'F-WN12-CC-000114_fix'
  tag version: 'WN12-CC-000114'
  tag ruleid: 'WN12-CC-000114_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Do not send additional data" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name: DontSendAdditionalData

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000114
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000114

end
