# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000027 - FTP servers must be configured to prevent access to the system drive.'

control 'WN12-GE-000027' do
  impact 1.0
  title 'FTP servers must be configured to prevent access to the system drive.'
  desc '
The FTP service allows remote users to access shared files and directories which could provide access to system resources and compromise the system, especially if the user can gain access to the root directory of the boot drive.
'
  tag 'stig','WN12-GE-000027'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000027_chk'
  tag fixid: 'F-WN12-GE-000027_fix'
  tag version: 'WN12-GE-000027'
  tag ruleid: 'WN12-GE-000027_rule'
  tag fixtext: '
Configure the system to prevent an FTP service from allowing access to the system drive.
'
  tag checktext: '
If FTP is not installed on the system, this is NA.  

Open a "Command Prompt".
Log on using an authenticated FTP account, and attempt to access the root of the boot drive with the following commands:

X:\>ftp 127.0.0.1
(Connected to "servername".
220 "servername" Microsoft FTP Service (Version 2.0).)

User: "ftpuser"
(331 Password required for ftpuser.)

Password: "password"
(230 User ftpuser logged in.)

ftp> dir

If the FTP session indicates access to areas of the operating system such as Program Files and Windows directories, this is a finding.
'

# START_DESCRIBE WN12-GE-000027
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000027

end
