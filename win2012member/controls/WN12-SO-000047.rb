# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000047 - IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'

control 'WN12-SO-000047' do
  impact 0.1
  title 'IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'
  desc '
Configuring Windows to limit the number of times that IPv6 TCP retransmits unacknowledged data segments before aborting the attempt helps prevent resources from becoming exhausted.
'
  tag 'stig','WN12-SO-000047'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000047_chk'
  tag fixid: 'F-WN12-SO-000047_fix'
  tag version: 'WN12-SO-000047'
  tag ruleid: 'WN12-SO-000047_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is the default)" to "3" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: TcpMaxDataRetransmissions

Type: REG_DWORD
Value: 3 (or less)
'

# START_DESCRIBE WN12-SO-000047
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000047

end
