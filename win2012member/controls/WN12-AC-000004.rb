# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AC-000004 - The password uniqueness must meet minimum requirements.'

control 'WN12-AC-000004' do
  impact 0.5
  title 'The password uniqueness must meet minimum requirements.'
  desc '
A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change to a unique password on a regularly scheduled basis.  This enables users to effectively negate the purpose of mandating periodic password changes.
'
  tag 'stig','WN12-AC-000004'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AC-000004_chk'
  tag fixid: 'F-WN12-AC-000004_fix'
  tag version: 'WN12-AC-000004'
  tag ruleid: 'WN12-AC-000004_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Enforce password history" to "5" passwords remembered.
'
  tag checktext: '
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for "Enforce password history" is less than "5" passwords remembered, this is a finding.
'

# START_DESCRIBE WN12-AC-000004
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AC-000004

end
