# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-CC-000081 - The Enhanced Mitigation Experience Toolkit (EMET) Default Protections for Popular Software must be enabled.'

control 'WN12-CC-000081' do
  impact 0.5
  title 'The Enhanced Mitigation Experience Toolkit (EMET) Default Protections for Popular Software must be enabled.'
  desc '
Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications, adding additional levels of protection.
'
  tag 'stig','WN12-CC-000081'
  tag severity: 'medium'
  tag checkid: 'C-WN12-CC-000081_chk'
  tag fixid: 'F-WN12-CC-000081_fix'
  tag version: 'WN12-CC-000081'
  tag ruleid: 'WN12-CC-000081_rule'
  tag fixtext: '
EMET 4.0
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> EMET -> "Default Protections for Popular Software" to "Enabled".

The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\EMET\Defaults\

EMET 4.0
The Value Names will include the following: 
7z
7zFM
7zGUI
Chrome
Firefox
FirefoxPluginContainer
FoxitReader
GoogleTalk
iTunes
LiveWriter
LyncCommunicator
mIRC
Opera
PhotoGallery
Photoshop
Pidgin
QuickTimePlayer
RealConverter
RealPlayer
Safari
SkyDrive
Skype
Thunderbird
ThunderbirdPluginContainer
UnRAR
VLC
Winamp
WindowsLiveMail
WindowsMediaPlayer
WinRARConsole
WinRARGUI
Winzip
Winzip64

If confirmed that none of the applications are installed on a system, this can be NA.
'

# START_DESCRIBE WN12-CC-000081
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-CC-000081

end
