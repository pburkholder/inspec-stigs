# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000046 - The system must be configured to prevent automatic forwarding of error information.'

control 'WN12-CC-000046' do
  impact 0.5
  title 'The system must be configured to prevent automatic forwarding of error information.'
  desc '
This setting controls the reporting of errors to Microsoft and, if defined, a corporate error reporting site.  This does not interfere with the reporting of errors to the local user.  Since the contents of memory are included in this error report, sensitive information may be transmitted to Microsoft.  This feature must be disabled to prevent the release of such information.
'
  tag 'stig','WN12-CC-000046'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000046_chk'
  tag fixid: 'F-WN12-CC-000046_fix'
  tag version: 'WN12-CC-000046'
  tag ruleid: 'WN12-CC-000046_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Windows Error Reporting" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\PCHealth\ErrorReporting\

Value Name: DoReport

Type: REG_DWORD
Value: 0

This setting may be enabled if the site has configured the option to send reports to a local error reporting server:  
Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting".
'

# START_DESCRIBE WN12-CC-000046
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000046

end
