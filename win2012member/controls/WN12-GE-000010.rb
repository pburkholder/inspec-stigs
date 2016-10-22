# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000010 - The system must not boot into multiple operating systems (dual-boot).'

control 'WN12-GE-000010' do
  impact 0.5
  title 'The system must not boot into multiple operating systems (dual-boot).'
  desc '
Allowing a system to boot into multiple operating systems (dual-booting) may allow security to be circumvented on a secure system.
'
  tag 'stig','WN12-GE-000010'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000010_chk'
  tag fixid: 'F-WN12-GE-000010_fix'
  tag version: 'WN12-GE-000010'
  tag ruleid: 'WN12-GE-000010_rule'
  tag fixtext: '
Ensure Windows Server 2012 is the only operating system installed for the system to boot into.  Remove alternate operating systems.
'
  tag checktext: '
Verify the local system boots directly into Windows.  

Open Control Panel.
Select "System".
Select the "Advanced System Settings" link.
Select the "Advanced" tab.
Click the "Startup and Recovery" Settings button.  

If the drop-down list box "Default operating system:" shows any operating system other than Windows Server 2012, this is a finding.
'

# START_DESCRIBE WN12-GE-000010
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000010

end
