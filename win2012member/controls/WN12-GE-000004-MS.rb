# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000004-MS - Only administrators responsible for the system must have Administrator rights on the system.'

control 'WN12-GE-000004-MS' do
  impact 1.0
  title 'Only administrators responsible for the system must have Administrator rights on the system.'
  desc '
An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary. 

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group.  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the built-in Administrators group.
'
  tag 'stig','WN12-GE-000004-MS'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000004-MS_chk'
  tag fixid: 'F-WN12-GE-000004-MS_fix'
  tag version: 'WN12-GE-000004-MS'
  tag ruleid: 'WN12-GE-000004-MS_rule'
  tag fixtext: '
Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain-joined member servers, replace the Domain Admins group with a domain member server administrator group.

Remove any standard user accounts.
'
  tag checktext: '
Review the local Administrators group. Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group.

Standard user accounts must not be members of the local Administrator group.

If prohibited accounts are members of the local Administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.
'

# START_DESCRIBE WN12-GE-000004-MS
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000004-MS

end
