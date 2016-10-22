# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000003 - The period of time before the bad logon counter is reset must meet minimum requirements.'

control 'WN12-AC-000003' do
  impact 0.5
  title 'The period of time before the bad logon counter is reset must meet minimum requirements.'
  desc '
The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to 0.  The smaller this value is, the less effective the account lockout feature will be in protecting the local system.
'
  tag 'stig','WN12-AC-000003'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000003_chk'
  tag fixid: 'F-WN12-AC-000003_fix'
  tag version: 'WN12-AC-000003'
  tag ruleid: 'WN12-AC-000003_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy -> "Reset account lockout counter after" to at least "60" minutes.
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "60" minutes, this is a finding.
'

# START_DESCRIBE WN12-AC-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000003

end
