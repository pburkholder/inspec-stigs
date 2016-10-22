# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000026 - FTP servers must be configured to prevent anonymous logons.'

control 'WN12-GE-000026' do
  impact 0.5
  title 'FTP servers must be configured to prevent anonymous logons.'
  desc '
The FTP (File Transfer Protocol) service allows remote users to access shared files and directories.  Allowing anonymous FTP connections makes user auditing difficult.

Using accounts that have administrator privileges to log on to FTP risks that the userid and password will be captured on the network and give administrator access to an unauthorized user.
'
  tag 'stig','WN12-GE-000026'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000026_chk'
  tag fixid: 'F-WN12-GE-000026_fix'
  tag version: 'WN12-GE-000026'
  tag ruleid: 'WN12-GE-000026_rule'
  tag fixtext: '
Configure the system to prevent an installed FTP service from allowing anonymous logons.
'
  tag checktext: '
If FTP is not installed on the system, this is NA.  

Open a "Command Prompt".
Attempt to log on as the user "anonymous" with the following commands:

C:\>ftp localhost
(Connected to "servername".
220 Microsoft FTP Service)

User: anonymous
(331 Anonymous access allowed, send identity (e-mail name) as password.)

Password: password
(230 User logged in.)
ftp>

If the command response indicates that an anonymous FTP login was permitted, this is a finding.

Severity Override:  If accounts with administrator privileges are used to access FTP, this becomes a CAT I finding.
'

# START_DESCRIBE WN12-GE-000026
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000026

end
