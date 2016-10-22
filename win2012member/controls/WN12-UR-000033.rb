# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000033 - Unauthorized accounts must not have the Modify an object label user right.'

control 'WN12-UR-000033' do
  impact 0.5
  title 'Unauthorized accounts must not have the Modify an object label user right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Modify an object label" user right can change the integrity label of an object.  This could potentially be used to execute code at a higher privilege.
'
  tag 'stig','WN12-UR-000033'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000033_chk'
  tag fixid: 'F-WN12-UR-000033_fix'
  tag version: 'WN12-UR-000033'
  tag ruleid: 'WN12-UR-000033_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Modify an object label" to be defined but containing no entries (blank).
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Modify an object label" user right, this is a finding.
'

# START_DESCRIBE WN12-UR-000033
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000033

end
