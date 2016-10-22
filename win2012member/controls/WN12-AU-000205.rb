# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-AU-000205 - Permissions for the Security event log must prevent access by nonprivileged accounts.'

control 'WN12-AU-000205' do
  impact 0.5
  title 'Permissions for the Security event log must prevent access by nonprivileged accounts.'
  desc '
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The Security event log may disclose sensitive information or be  susceptible to tampering if proper permissions are not applied.
'
  tag 'stig','WN12-AU-000205'
  tag severity: 'medium'
  tag checkid: 'C-WN12-AU-000205_chk'
  tag fixid: 'F-WN12-AU-000205_fix'
  tag version: 'WN12-AU-000205'
  tag ruleid: 'WN12-AU-000205_rule'
  tag fixtext: '
Ensure the permissions on the System event log (System.evtx) are configured to prevent standard user accounts or groups from having access.  The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\Eventlog".
'
  tag checktext: '
Verify the permissions on the Security event log (Security.evtx).  Standard user accounts or groups must not have access.  The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.  They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.
'

# START_DESCRIBE WN12-AU-000205
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-AU-000205

end
