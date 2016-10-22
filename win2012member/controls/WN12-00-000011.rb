# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000011 - Application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'

control 'WN12-00-000011' do
  impact 0.5
  title 'Application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
  desc '
Setting application accounts to expire may cause applications to stop functioning.  However, not changing them on a regular basis  exposes them to attack.  The site will have a policy that application account passwords are changed at least annually or when a system administrator with knowledge of the password leaves the organization.
'
  tag 'stig','WN12-00-000011'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000011_chk'
  tag fixid: 'F-WN12-00-000011_fix'
  tag version: 'WN12-00-000011'
  tag ruleid: 'WN12-00-000011_rule'
  tag fixtext: '
Establish a site policy that defines the requirements for application/service account password changes.

Change application/service account passwords that are manually managed and entered by a system administrator at least annually or whenever an administrator with knowledge of the password leaves the organization.
'
  tag checktext: '
The site must have a policy to ensure passwords for manually managed application/service accounts are changed at least annually or whenever a system administrator that has knowledge of the password leaves the organization.  If such a policy does not exist or has not been implemented, this is a finding.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PwsdLastSetTime 
AcctDisabled

If any application accounts listed have a date older than one year in the "PwsdLastSetTime" column, this is a finding.
'

# START_DESCRIBE WN12-00-000011
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000011

end
