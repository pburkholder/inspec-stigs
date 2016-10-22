# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000003 - The built-in guest account must be disabled.'

control 'WN12-SO-000003' do
  impact 0.5
  title 'The built-in guest account must be disabled.'
  desc '
A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned.
'
  tag 'stig','WN12-SO-000003'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000003_chk'
  tag fixid: 'F-WN12-SO-000003_fix'
  tag version: 'WN12-SO-000003'
  tag ruleid: 'WN12-SO-000003_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Guest account status" to "Disabled".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.
'

# START_DESCRIBE WN12-SO-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000003

end
