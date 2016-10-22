# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000074 - Autoplay must be disabled for all drives.'

control 'WN12-CC-000074' do
  impact 1.0
  title 'Autoplay must be disabled for all drives.'
  desc '
Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon media is inserted into the drive.  As a result, the setup file of programs or music on audio media may start.  By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives.  Enabling this policy disables autoplay on all drives.
'
  tag 'stig','WN12-CC-000074'
  tag severity: 'high'
  tag checkid: 'C-WN12-CC-000074_chk'
  tag fixid: 'F-WN12-CC-000074_fix'
  tag version: 'WN12-CC-000074'
  tag ruleid: 'WN12-CC-000074_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Turn off AutoPlay" to "Enabled:All Drives".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\

Value Name: NoDriveTypeAutoRun

Type: REG_DWORD
Value: 0x000000ff (255)
'

# START_DESCRIBE WN12-CC-000074
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000074

end
