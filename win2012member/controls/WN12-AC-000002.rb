# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000002 - The number of allowed bad logon attempts must meet minimum requirements.'

control 'WN12-AC-000002' do
  impact 0.5
  title 'The number of allowed bad logon attempts must meet minimum requirements.'
  desc '
The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.
'
  tag 'stig','WN12-AC-000002'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000002_chk'
  tag fixid: 'F-WN12-AC-000002_fix'
  tag version: 'WN12-AC-000002'
  tag ruleid: 'WN12-AC-000002_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy -> "Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable).
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.
'

# START_DESCRIBE WN12-AC-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000002

end
