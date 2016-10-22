# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000129 - Automatic Updates must not be used (unless configured to point to a DoD server).'

control 'WN12-CC-000129' do
  impact 0.5
  title 'Automatic Updates must not be used (unless configured to point to a DoD server).'
  desc '
Uncontrolled system updates can introduce issues to a system.  The system must be configured to prevent Automatic Updates from being run unless directed to a DoD Windows Server Update Services (WSUS) server.
'
  tag 'stig','WN12-CC-000129'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000129_chk'
  tag fixid: 'F-WN12-CC-000129_fix'
  tag version: 'WN12-CC-000129'
  tag ruleid: 'WN12-CC-000129_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Update -> "Configure Automatic Updates" to "Disabled". 

If the site is using a DoD WSUS server to distribute software updates, the policy setting to configure the WSUS URL is Computer Configuration -> Administrative Templates -> Windows Components -> Windows Update -> "Specify intranet Microsoft update service location".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WindowsUpdate\AU\

Value Name: NoAutoUpdate
Type: REG_DWORD
Value: 1

If the site is using a DoD WSUS server to distribute software updates, and the computer is configured to point at that server, this can be set to "Enabled".   In this instance, the setting will not be considered a finding.   
To determine whether WSUS is being used, verify the following registry key value exists and is pointing to an organizational or DoD WSUS URL: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WindowsUpdate\

Value Name: WUServer

Type: REG_SZ
Value: "URL of DoD WSUS"
'

# START_DESCRIBE WN12-CC-000129
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000129

end
