# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000005 - The maximum password age must meet requirements.'

control 'WN12-AC-000005' do
  impact 0.5
  title 'The maximum password age must meet requirements.'
  desc '
The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.
'
  tag 'stig','WN12-AC-000005'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000005_chk'
  tag fixid: 'F-WN12-AC-000005_fix'
  tag version: 'WN12-AC-000005'
  tag ruleid: 'WN12-AC-000005_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Maximum Password Age" to "60" days or less (excluding "0" which is unacceptable).
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for the "Maximum password age" is greater than "60" days, this is a finding.  If the value is set to "0" (never expires), this is a finding.
'

# START_DESCRIBE WN12-AC-000005
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000005

end
