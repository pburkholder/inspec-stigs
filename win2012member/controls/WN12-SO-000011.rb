# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000011 - Ejection of removable NTFS media must be restricted to Administrators.'

control 'WN12-SO-000011' do
  impact 0.5
  title 'Ejection of removable NTFS media must be restricted to Administrators.'
  desc '
Removable hard drives, if they are not properly configured, can be formatted and ejected by users who are not members of the Administrators Group.  Formatting and ejecting removable NTFS media must only be done by administrators.
'
  tag 'stig','WN12-SO-000011'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000011_chk'
  tag fixid: 'F-WN12-SO-000011_fix'
  tag version: 'WN12-SO-000011'
  tag ruleid: 'WN12-SO-000011_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Allowed to format and eject removable media" to "Administrators".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon

Value Name: AllocateDASD

Value Type: REG_SZ
Value: 0
'

# START_DESCRIBE WN12-SO-000011
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000011

end
