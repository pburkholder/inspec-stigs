# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000024 - Caching of logon credentials must be limited.'

control 'WN12-SO-000024' do
  impact 0.1
  title 'Caching of logon credentials must be limited.'
  desc '
The default Windows configuration caches the last logon credentials for users who log on interactively to a system.  This feature is provided for system availability reasons, such as the user\'s machine being disconnected from the network or domain controllers being unavailable.  Even though the credential cache is well protected, storing encrypted copies of users\' passwords on workstations does not always have the same physical protection required for domain controllers.  If a workstation is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain.
'
  tag 'stig','WN12-SO-000024'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000024_chk'
  tag fixid: 'F-WN12-SO-000024_fix'
  tag version: 'WN12-SO-000024'
  tag ruleid: 'WN12-SO-000024_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Number of previous logons to cache (in case domain controller is not available)" to "4" logons or less.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: CachedLogonsCount

Value Type: REG_SZ
Value: 4 (or less)
'

# START_DESCRIBE WN12-SO-000024
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000024

end
