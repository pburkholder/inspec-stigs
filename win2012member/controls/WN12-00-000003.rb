# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000003 - The system must not use removable media as the boot loader.'

control 'WN12-00-000003' do
  impact 1.0
  title 'The system must not use removable media as the boot loader.'
  desc '
Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.
'
  tag 'stig','WN12-00-000003'
  tag severity: 'high'
  tag checkid: 'C-WN12-00-000003_chk'
  tag fixid: 'F-WN12-00-000003_fix'
  tag version: 'WN12-00-000003'
  tag ruleid: 'WN12-00-000003_rule'
  tag fixtext: '
Configure the system to use a boot loader installed on fixed media.
'
  tag checktext: '
On systems with a BIOS or system controller, verify whether the system allows removable media for the boot loader.  If it does, this is a finding.
'

# START_DESCRIBE WN12-00-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000003

end
