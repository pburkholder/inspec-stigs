# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-FW-000026 - The Windows Firewall log file name and location must be configured for the Public Profile.'

control 'WN12-FW-000026' do
  impact 0.1
  title 'The Windows Firewall log file name and location must be configured for the Public Profile.'
  desc '
A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  The location and file name of the firewall log for a public network connection will be defined  to ensure the logs are maintained.
'
  tag 'stig','WN12-FW-000026'
  tag severity: 'low'
  tag checkid: 'C-WN12-FW-000026_chk'
  tag fixid: 'F-WN12-FW-000026_fix'
  tag version: 'WN12-FW-000026'
  tag ruleid: 'WN12-FW-000026_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Public Profile Tab -> Logging (select Customize), "Name" to "%windir%\system32\logfiles\firewall\publicfirewall.log".

Configure a comparable setting if a third-party firewall is used.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\

Value Name: LogFilePath

Type: REG_SZ
Value: %windir%\system32\logfiles\firewall\publicfirewall.log

Automated tools may search for the file name specified in the check.  If the site uses a different name for the log file, the finding will need to be closed manually.

If a third-party firewall is used, verify a comparable setting has been implemented.
'

# START_DESCRIBE WN12-FW-000026
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-FW-000026

end
