# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000020 - Software certificate installation files must be removed from a system.'

control 'WN12-GE-000020' do
  impact 0.5
  title 'Software certificate installation files must be removed from a system.'
  desc '
Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.
'
  tag 'stig','WN12-GE-000020'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000020_chk'
  tag fixid: 'F-WN12-GE-000020_fix'
  tag version: 'WN12-GE-000020'
  tag ruleid: 'WN12-GE-000020_rule'
  tag fixtext: '
Remove any certificate installation files (*.p12 and *.pfx) found on a system.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).
'
  tag checktext: '
Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).  Some applications create files with extensions of .p12 that are NOT certificate installation files.  Removal of noncertificate installation files from systems is not required.  These must be documented with the IAO.
'

# START_DESCRIBE WN12-GE-000020
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000020

end
