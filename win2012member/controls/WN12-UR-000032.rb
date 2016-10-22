# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-UR-000032 - Unauthorized accounts must not have the Manage auditing and security log user right.'

control 'WN12-UR-000032' do
  impact 0.5
  title 'Unauthorized accounts must not have the Manage auditing and security log user right.'
  desc '
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations.  This could be used to clear evidence of tampering.
'
  tag 'stig','WN12-UR-000032'
  tag severity: 'medium'
  tag checkid: 'C-WN12-UR-000032_chk'
  tag fixid: 'F-WN12-UR-000032_fix'
  tag version: 'WN12-UR-000032'
  tag ruleid: 'WN12-UR-000032_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Manage auditing and security log" to only include the following accounts or groups:

Administrators
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Manage auditing and security log" user right, this is a finding:

Administrators

If the site has an Auditors group that further limits this privilege this would not be a finding.
'

# START_DESCRIBE WN12-UR-000032
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-UR-000032

end
