# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000072 - Autoplay must be turned off for non-volume devices.'

control 'WN12-CC-000072' do
  impact 1.0
  title 'Autoplay must be turned off for non-volume devices.'
  desc '
Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as media is inserted into the drive.  As a result, the setup file of programs or music on audio media may start.  This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).
'
  tag 'stig','WN12-CC-000072'
  tag severity: 'high'
  tag checkid: 'C-WN12-CC-000072_chk'
  tag fixid: 'F-WN12-CC-000072_fix'
  tag version: 'WN12-CC-000072'
  tag ruleid: 'WN12-CC-000072_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Disallow Autoplay for non-volume devices" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoAutoplayfornonVolume

Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-CC-000072
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000072

end
