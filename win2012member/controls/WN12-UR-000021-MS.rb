# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000021-MS - The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems, and from unauthenticated access on all systems.'

control 'WN12-UR-000021-MS' do
  impact 0.5
  title 'The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems, and from unauthenticated access on all systems.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on through Remote Desktop Services" user right defines the accounts that are prevented from logging on using Remote Desktop Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local administrator accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.
'
  tag 'stig','WN12-UR-000021-MS'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000021-MS_chk'
  tag fixid: 'F-WN12-UR-000021-MS_fix'
  tag version: 'WN12-UR-000021-MS'
  tag ruleid: 'WN12-UR-000021-MS_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on through Remote Desktop Services" to include the following:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group
*All Local Administrator Accounts

All Systems:
Guests Group

*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop Services" user right, this is a finding:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group
*All Local Administrator Accounts

All Systems:
Guests Group

*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.
'

# START_DESCRIBE WN12-UR-000021-MS
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000021-MS

end
