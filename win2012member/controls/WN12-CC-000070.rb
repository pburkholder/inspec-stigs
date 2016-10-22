# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000070 - Trusted app installation must be enabled to allow for signed enterprise line of business apps.'

control 'WN12-CC-000070' do
  impact 0.1
  title 'Trusted app installation must be enabled to allow for signed enterprise line of business apps.'
  desc '
Enabling trusted app installation allows for enterprise line of business Windows 8 type apps.   A trusted app package is one that is signed with a certificate chain that can be successfully validated in the enterprise.  Configuring this ensures enterprise line of business apps are accessible.
'
  tag 'stig','WN12-CC-000070'
  tag severity: 'low'
  tag checkid: 'C-WN12-CC-000070_chk'
  tag fixid: 'F-WN12-CC-000070_fix'
  tag version: 'WN12-CC-000070'
  tag ruleid: 'WN12-CC-000070_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> App Package Deployment  -> "Allow all trusted apps to install" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Appx\

Value Name: AllowAllTrustedApps

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000070
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000070

end
