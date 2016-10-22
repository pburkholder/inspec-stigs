# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000013 - Local users must not exist on a system in a domain.'

control 'WN12-GE-000013' do
  impact 0.1
  title 'Local users must not exist on a system in a domain.'
  desc '
To minimize potential points of attack, local users, other than built-in accounts such as Administrator and Guest accounts, must not exist on a workstation in a domain.  Users must log onto workstations in a domain with their domain accounts.
'
  tag 'stig','WN12-GE-000013'
  tag severity: 'low'
  tag checkid: 'C-WN12-GE-000013_chk'
  tag fixid: 'F-WN12-GE-000013_fix'
  tag version: 'WN12-GE-000013'
  tag ruleid: 'WN12-GE-000013_rule'
  tag fixtext: '
Configure domain-joined systems to restrict the existence of local user accounts.  Remove any unauthorized local accounts.
'
  tag checktext: '
This requirement is NA for nondomain-joined systems.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
AcctDisabled
Groups

If local users other than the built-in accounts listed below exist on a workstation in a domain, this is a finding:

Built-in administrator account (SID ending in 500)
Built-in guest account (SID ending in 501)

If a site has need of special purpose local user accounts, this must be documented with the IAO.
'

# START_DESCRIBE WN12-GE-000013
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000013

end
