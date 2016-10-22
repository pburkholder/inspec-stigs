# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000002 - System BIOS or system controllers supporting password protection must have administrator accounts/passwords only configured, and no others.'

control 'WN12-00-000002' do
  impact 0.5
  title 'System BIOS or system controllers supporting password protection must have administrator accounts/passwords only configured, and no others.'
  desc '
A system\'s BIOS or system controller handles the initial startup of a system, and its configuration must be protected from unauthorized modification.  When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators.  Failure to protect BIOS or system controller settings could result in Denial of Service or compromise of the system resulting from unauthorized configuration changes.
'
  tag 'stig','WN12-00-000002'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000002_chk'
  tag fixid: 'F-WN12-00-000002_fix'
  tag version: 'WN12-00-000002'
  tag ruleid: 'WN12-00-000002_rule'
  tag fixtext: '
Access the system\'s BIOS or system controller.  Set a supervisor/administrator password if one has not been set. Disable a user-level password if one has been set.
'
  tag checktext: '
On systems with a BIOS or system controller, verify a supervisor or administrator password is set.  If a password is not set, this is a finding.

If the BIOS or system controller supports user-level access in addition to supervisor/administrator access, determine whether this access is enabled.  If so, this is a finding.
'

# START_DESCRIBE WN12-00-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000002

end
