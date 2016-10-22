# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000001 - The lockout duration must be configured to require an administrator to unlock an account.'

control 'WN12-AC-000001' do
  impact 0.5
  title 'The lockout duration must be configured to require an administrator to unlock an account.'
  desc '
The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.  A value of 0 will require an administrator to unlock the account.
'
  tag 'stig','WN12-AC-000001'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000001_chk'
  tag fixid: 'F-WN12-AC-000001_fix'
  tag version: 'WN12-AC-000001'
  tag ruleid: 'WN12-AC-000001_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy -> "Account lockout duration" to "0" minutes, "Account is locked out until administrator unlocks it".
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy.

If the "Account lockout duration" is not set to "0", requiring an administrator to unlock the account, this is a finding.
'

# START_DESCRIBE WN12-AC-000001
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000001

end
