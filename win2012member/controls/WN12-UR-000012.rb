# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000012 - Unauthorized accounts must not have the Create a token object user right.'

control 'WN12-UR-000012' do
  impact 1.0
  title 'Unauthorized accounts must not have the Create a token object user right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Create a token object" user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system.
'
  tag 'stig','WN12-UR-000012'
  tag severity: 'high'
  tag checkid: 'C-WN12-UR-000012_chk'
  tag fixid: 'F-WN12-UR-000012_fix'
  tag version: 'WN12-UR-000012'
  tag ruleid: 'WN12-UR-000012_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Create a token object" to be defined but containing no entries (blank).
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Create a token object" user right, this is a finding.

Severity Override:  If an application requires this user right, this can be downgraded to a CAT III if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the IAO.
The application account must meet requirements for application account passwords, such as length (V-36661) and required changes frequency (V-36662).
'

# START_DESCRIBE WN12-UR-000012
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000012

end
