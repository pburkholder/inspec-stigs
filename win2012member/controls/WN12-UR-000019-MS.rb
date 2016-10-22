# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000019-MS - The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.'

control 'WN12-UR-000019-MS' do
  impact 0.5
  title 'The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied log on as a service.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.
'
  tag 'stig','WN12-UR-000019-MS'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000019-MS_chk'
  tag fixid: 'F-WN12-UR-000019-MS_fix'
  tag version: 'WN12-UR-000019-MS'
  tag ruleid: 'WN12-UR-000019-MS_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include the following for domain-joined systems:

Enterprise Admins Group
Domain Admins Group

Configure the "Deny log on as a service" for nondomain systems to include no entries (blank).
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" user right on domain-joined systems, this is a finding:

Enterprise Admins Group
Domain Admins Group

If any accounts or groups are defined for the "Deny log on as a service" user right on non-domain-joined systems, this is a finding.
'

# START_DESCRIBE WN12-UR-000019-MS
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000019-MS

end
