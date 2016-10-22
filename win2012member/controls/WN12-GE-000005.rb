# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000005 - Local volumes must be formatted using NTFS.'

control 'WN12-GE-000005' do
  impact 1.0
  title 'Local volumes must be formatted using NTFS.'
  desc '
The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system.  To support this, volumes must be formatted using the NTFS file system.
'
  tag 'stig','WN12-GE-000005'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000005_chk'
  tag fixid: 'F-WN12-GE-000005_fix'
  tag version: 'WN12-GE-000005'
  tag ruleid: 'WN12-GE-000005_rule'
  tag fixtext: '
Format all partitions/drives to use NTFS.
'
  tag checktext: '
Open the Computer Management Console.
Expand the "Storage" object in the Tree window.
Select the "Disk Management" object.

If the file system column does not indicate "NTFS" as the file system for each local hard drive, this is a finding.

Some hardware vendors create a small FAT partition to store troubleshooting and recovery data. No other files must be stored here.  This must be documented with the IAO.
'

# START_DESCRIBE WN12-GE-000005
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000005

end
