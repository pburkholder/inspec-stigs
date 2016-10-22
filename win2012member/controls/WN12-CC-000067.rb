# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000067 - Access to Windows Online Troubleshooting Service (WOTS) must be prevented.'

control 'WN12-CC-000067' do
  impact 0.1
  title 'Access to Windows Online Troubleshooting Service (WOTS) must be prevented.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from searching troubleshooting content on Microsoft servers.  Only local content will be available.
'
  tag 'stig','WN12-CC-000067'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000067_chk'
  tag fixid: 'F-WN12-CC-000067_fix'
  tag version: 'WN12-CC-000067'
  tag ruleid: 'WN12-CC-000067_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Scripted Diagnostics -> "Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via Windows Online Troubleshooting Service - WOTS)" to "Disabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\

Value Name: EnableQueryRemoteServer

Type: REG_DWORD
Value: 0
'

# START_DESCRIBE WN12-CC-000067
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000067

end
