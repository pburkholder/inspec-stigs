# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000026 - Unauthorized accounts must not have the Increase a process working set user right.'

control 'WN12-UR-000026' do
  impact 0.5
  title 'Unauthorized accounts must not have the Increase a process working set user right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Increase a process working set" user right can change the size of a process\'s working set, potentially causing performance issues or a DoS.
'
  tag 'stig','WN12-UR-000026'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000026_chk'
  tag fixid: 'F-WN12-UR-000026_fix'
  tag version: 'WN12-UR-000026'
  tag ruleid: 'WN12-UR-000026_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Increase a process working set" to only include the following accounts or groups:

Administrators
Local Service
Window Manager\Window Manager Group
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Increase a process working set" user right, this is a finding:

Administrators
Local Service
Window Manager\Window Manager Group
'

# START_DESCRIBE WN12-UR-000026
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000026

end
