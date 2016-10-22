# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000025 - Unauthorized accounts must not have the Impersonate a client after authentication user right.'

control 'WN12-UR-000025' do
  impact 0.5
  title 'Unauthorized accounts must not have the Impersonate a client after authentication user right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf.  An attacker could potentially use this to elevate privileges.
'
  tag 'stig','WN12-UR-000025'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000025_chk'
  tag fixid: 'F-WN12-UR-000025_fix'
  tag version: 'WN12-UR-000025'
  tag ruleid: 'WN12-UR-000025_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Impersonate a client after authentication" to only include the following accounts or groups:

Administrators
Service
Local Service
Network Service
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Impersonate a client after authentication" user right, this is a finding:

Administrators
Service
Local Service
Network Service

Severity Override:  If an application requires this user right, this can be downgraded to not a finding if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the IAO.
The application account must meet requirements for application account passwords, such as length (V-36661) and required changes frequency (V-36662).
'

# START_DESCRIBE WN12-UR-000025
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000025

end
