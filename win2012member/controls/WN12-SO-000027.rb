# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000027 - The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'

control 'WN12-SO-000027' do
  impact 0.5
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc '
Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.
'
  tag 'stig','WN12-SO-000027'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000027_chk'
  tag fixid: 'F-WN12-SO-000027_fix'
  tag version: 'WN12-SO-000027'
  tag ruleid: 'WN12-SO-000027_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Smart card removal behavior" to  "Lock Workstation" or "Force Logoff".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
 
Value Name: SCRemoveOption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

If configuring this on servers causes issues such as terminating users\' remote sessions and the site has a policy in place that any other sessions on the servers such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the IAO.
'

# START_DESCRIBE WN12-SO-000027
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000027

end
