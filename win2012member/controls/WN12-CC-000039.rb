# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000039 - Printing over HTTP must be prevented.'

control 'WN12-CC-000039' do
  impact 0.5
  title 'Printing over HTTP must be prevented.'
  desc '
Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.
'
  tag 'stig','WN12-CC-000039'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000039_chk'
  tag fixid: 'F-WN12-CC-000039_fix'
  tag version: 'WN12-CC-000039'
  tag ruleid: 'WN12-CC-000039_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off printing over HTTP" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Printers\

Value Name: DisableHTTPPrinting

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000039
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000039

end
