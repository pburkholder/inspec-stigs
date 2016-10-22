# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000004 - Unauthorized accounts must not have the Adjust memory quotas for a process user right.'

control 'WN12-UR-000004' do
  impact 0.5
  title 'Unauthorized accounts must not have the Adjust memory quotas for a process user right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Adjust memory quotas for a process" user right can adjust memory that is available to processes, and could be used in a denial of service (DoS) attack.
'
  tag 'stig','WN12-UR-000004'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000004_chk'
  tag fixid: 'F-WN12-UR-000004_fix'
  tag version: 'WN12-UR-000004'
  tag ruleid: 'WN12-UR-000004_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Adjust memory quotas for a process" to only include the following accounts or groups:

Administrators
Local Service
Network Service
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Adjust memory quotas for a process" user right, this is a finding:

Administrators
Local Service
Network Service

Severity Override:  If an application requires this user right, this can be downgraded to not a finding if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the IAO.
The application account must meet requirements for application account passwords, such as length (V-36661) and required changes frequency (V-36662).
'

# START_DESCRIBE WN12-UR-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000004

end
